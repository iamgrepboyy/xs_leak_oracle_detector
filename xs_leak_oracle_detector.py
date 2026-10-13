"""Differential XS-Leak oracle detector for Burp's legacy Jython API."""

import re
import threading
from datetime import datetime

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.lang import Runnable, System
from java.net import URL
from java.util import ArrayList
from javax.swing import (
    JButton,
    JCheckBox,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSplitPane,
    ListSelectionModel,
    SwingUtilities,
    SwingWorker,
    JTable,
    JTextArea,
    JTextField,
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import DefaultTableModel


_DEFAULT_IDENTITY_HEADERS = "Cookie, Authorization, X-CSRF-Token, X-XSRF-Token"
_BLOCKED_HEADERS = set(
    ["host", "content-length", "transfer-encoding", "connection"]
)
_OBSERVATION_LIMIT = 300
_ROLE_LIMIT = 12
_MAX_SELECTED_ROLES = 6
_MAX_ROUNDS = 5
_TIMING_THRESHOLD_MS = 100.0
_DIFF_HEADERS = [
    "cache-control",
    "x-frame-options",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "vary",
    "location",
]


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _Runnable(Runnable):
    def __init__(self, callback):
        self.callback = callback

    def run(self):
        self.callback()


class _SelectionListener(ListSelectionListener):
    def __init__(self, callback):
        self.callback = callback

    def valueChanged(self, event):
        self.callback(event)


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


def _median(values):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def _mode(values):
    if not values:
        return ""
    selected = values[0]
    selected_count = values.count(selected)
    for value in values[1:]:
        count = values.count(value)
        if count > selected_count:
            selected = value
            selected_count = count
    return selected


def _parse_identity_headers(value):
    names = []
    seen = set()
    for candidate in value.split(","):
        name = candidate.strip()
        if not name or not re.match(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", name):
            continue
        normalized = name.lower()
        if normalized in _BLOCKED_HEADERS or normalized in seen:
            continue
        seen.add(normalized)
        names.append(name)
    return names


def _header_name(header):
    if ":" not in header:
        return ""
    return header.split(":", 1)[0].strip().lower()


def _response_metrics(helpers, response, elapsed_ms):
    response_info = helpers.analyzeResponse(response)
    headers = {}
    for line in response_info.getHeaders():
        line = str(line)
        name = _header_name(line)
        if not name:
            continue
        value = line.split(":", 1)[1].strip()
        if name in headers:
            headers[name] += ", " + value
        else:
            headers[name] = value

    for name in _DIFF_HEADERS:
        headers.setdefault(name, "<absent>")

    status = int(response_info.getStatusCode())
    location = headers["location"]
    if 300 <= status < 400 and location != "<absent>":
        redirect = "%d -> %s" % (status, location)
    else:
        redirect = "No redirect"
    return {
        "status": status,
        "body_length": len(response) - int(response_info.getBodyOffset()),
        "time_ms": elapsed_ms,
        "headers": headers,
        "redirect": redirect,
    }


def _aggregate_samples(samples):
    return {
        "status": _mode([sample["status"] for sample in samples]),
        "body_length": _median([sample["body_length"] for sample in samples]),
        "time_ms": _median([sample["time_ms"] for sample in samples]),
        "headers": dict(
            (name, _mode([sample["headers"][name] for sample in samples]))
            for name in _DIFF_HEADERS
        ),
        "redirect": _mode([sample["redirect"] for sample in samples]),
    }


def _compare_metrics(first, second):
    signals = []
    if first["status"] != second["status"]:
        signals.append("status %s/%s" % (first["status"], second["status"]))
    if first["body_length"] != second["body_length"]:
        signals.append(
            "body length %d/%d bytes"
            % (first["body_length"], second["body_length"])
        )
    timing_delta = abs(first["time_ms"] - second["time_ms"])
    if timing_delta >= _TIMING_THRESHOLD_MS:
        signals.append("timing delta %.0f ms" % timing_delta)
    if first["redirect"] != second["redirect"]:
        signals.append("redirect behavior differs")
    for name in _DIFF_HEADERS:
        first_value = first["headers"].get(name, "<absent>")
        second_value = second["headers"].get(name, "<absent>")
        if first_value != second_value:
            signals.append("%s differs" % name)
    return signals, timing_delta


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.RLock()
        self.observations = []
        self.displayed_observations = []
        self.roles = []
        self.displayed_roles = []
        self.results = []
        self.target = None
        self.running = False
        callbacks.setExtensionName("XS-Leak Oracle Detector")
        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("XS-Leak Oracle Detector loaded")

    def getTabCaption(self):
        return "XS-Leak Oracles"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if message_is_request or self.running:
            return
        try:
            request = message_info.getRequest()
            response = message_info.getResponse()
            service = message_info.getHttpService()
            if request is None or response is None or service is None:
                return
            request_info = self.helpers.analyzeRequest(service, request)
            url = request_info.getUrl()
            if not self.callbacks.isInScope(url):
                return
            response_info = self.helpers.analyzeResponse(response)
            observation = {
                "key": "%s %s" % (request_info.getMethod(), url),
                "method": str(request_info.getMethod()),
                "url": str(url),
                "status": int(response_info.getStatusCode()),
                "body_length": len(response) - int(response_info.getBodyOffset()),
                "observed_at": datetime.now().strftime("%H:%M:%S"),
                "request": request,
                "service": service,
            }
            with self.lock:
                self.observations = [
                    existing
                    for existing in self.observations
                    if existing["key"] != observation["key"]
                ]
                self.observations.insert(0, observation)
                self.observations = self.observations[:_OBSERVATION_LIMIT]
            SwingUtilities.invokeLater(_Runnable(self._refresh_observations))
        except Exception as error:
            self.callbacks.printError("XS-Leak traffic observation failed: " + str(error))

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        message_info = messages[0]
        menu_items = ArrayList()
        target_item = JMenuItem("Set request as XS-Leak comparison target")
        target_item.addActionListener(
            _Action(lambda: self._set_target_from_message(message_info))
        )
        role_item = JMenuItem("Capture request as XS-Leak user/state")
        role_item.addActionListener(
            _Action(lambda: self._capture_role(message_info))
        )
        menu_items.add(target_item)
        menu_items.add(role_item)
        return menu_items

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.set_target_button = JButton("Use selected traffic")
        self.set_target_button.addActionListener(_Action(self._use_selected_observation))
        self.compare_button = JButton("Compare selected roles")
        self.compare_button.addActionListener(_Action(self._compare_selected_roles))
        self.remove_role_button = JButton("Remove role")
        self.remove_role_button.addActionListener(_Action(self._remove_selected_roles))
        self.clear_button = JButton("Clear results")
        self.clear_button.addActionListener(_Action(self._clear_results))
        controls.add(self.set_target_button)
        controls.add(self.compare_button)
        controls.add(self.remove_role_button)
        controls.add(self.clear_button)
        controls.add(JLabel("Identity headers:"))
        self.identity_headers = JTextField(_DEFAULT_IDENTITY_HEADERS, 34)
        controls.add(self.identity_headers)
        controls.add(JLabel("Rounds:"))
        self.rounds_field = JTextField("3", 2)
        controls.add(self.rounds_field)
        self.allow_unsafe_box = JCheckBox("Allow non-GET/HEAD replay", False)
        controls.add(self.allow_unsafe_box)
        self.panel.add(controls, BorderLayout.NORTH)

        self.observation_model = _ReadOnlyModel(
            ["Time", "Method", "HTTP", "Body bytes", "URL"], 0
        )
        self.observation_table = JTable(self.observation_model)
        self.observation_table.setAutoCreateRowSorter(True)

        self.role_model = _ReadOnlyModel(["User/state", "Origin", "Captured identity headers"], 0)
        self.role_table = JTable(self.role_model)
        self.role_table.setAutoCreateRowSorter(True)
        self.role_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        observation_panel = JPanel(BorderLayout(4, 4))
        observation_panel.add(JLabel("Observed in-scope HTTP traffic"), BorderLayout.NORTH)
        observation_panel.add(JScrollPane(self.observation_table), BorderLayout.CENTER)
        role_panel = JPanel(BorderLayout(4, 4))
        role_panel.add(JLabel("Captured identity states (memory only)"), BorderLayout.NORTH)
        role_panel.add(JScrollPane(self.role_table), BorderLayout.CENTER)
        upper_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, observation_panel, role_panel
        )
        upper_split.setResizeWeight(0.58)

        self.result_model = _ReadOnlyModel(
            ["Target", "Compared users/states", "Signals", "Delta ms", "Assessment"], 0
        )
        self.result_table = JTable(self.result_model)
        self.result_table.setAutoCreateRowSorter(True)
        self.result_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._show_selected_result)
        )
        self.result_details = JTextArea(5, 80)
        self.result_details.setEditable(False)
        self.result_details.setLineWrap(True)
        results_split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self.result_table),
            JScrollPane(self.result_details),
        )
        results_split.setResizeWeight(0.7)
        results_panel = JPanel(BorderLayout(4, 4))
        results_panel.add(JLabel("Differential results"), BorderLayout.NORTH)
        results_panel.add(results_split, BorderLayout.CENTER)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, upper_split, results_panel)
        main_split.setResizeWeight(0.48)
        self.panel.add(main_split, BorderLayout.CENTER)

        footer = JPanel(BorderLayout())
        self.target_label = JLabel("Target: none")
        self.status_label = JLabel(
            "Choose an endpoint and two captured states. Timing differences of 100 ms or more are flagged."
        )
        footer.add(self.target_label, BorderLayout.NORTH)
        footer.add(self.status_label, BorderLayout.SOUTH)
        self.panel.add(footer, BorderLayout.SOUTH)

    def _refresh_observations(self):
        with self.lock:
            rows = list(self.observations)
            self.displayed_observations = rows
        self.observation_model.setRowCount(0)
        for item in rows:
            self.observation_model.addRow(
                [
                    item["observed_at"],
                    item["method"],
                    str(item["status"]),
                    str(item["body_length"]),
                    item["url"],
                ]
            )

    def _refresh_roles(self):
        self.displayed_roles = list(self.roles)
        self.role_model.setRowCount(0)
        for role in self.roles:
            self.role_model.addRow(
                [role["name"], role["origin"], role["captured_headers"]]
            )

    def _set_target_from_message(self, message_info):
        service = message_info.getHttpService()
        request = message_info.getRequest()
        if service is None or request is None:
            self.status_label.setText("The selected item has no HTTP request/service.")
            return
        self._set_target(service, request)

    def _set_target(self, service, request):
        try:
            request_info = self.helpers.analyzeRequest(service, request)
            self.target = {
                "service": service,
                "request": request,
                "url": str(request_info.getUrl()),
                "method": str(request_info.getMethod()).upper(),
            }
            self.target_label.setText(
                "Target: %s %s" % (self.target["method"], self.target["url"])
            )
            self.status_label.setText(
                "Target loaded. Only configured identity headers will be replaced."
            )
        except Exception as error:
            self.status_label.setText("Could not load target: " + str(error))

    def _use_selected_observation(self):
        row = self.observation_table.getSelectedRow()
        if row < 0:
            self.status_label.setText("Select an observed request first.")
            return
        model_row = self.observation_table.convertRowIndexToModel(row)
        with self.lock:
            if model_row >= len(self.displayed_observations):
                return
            observation = self.displayed_observations[model_row]
        self._set_target(observation["service"], observation["request"])

    def _capture_role(self, message_info):
        if self.running:
            return
        service = message_info.getHttpService()
        request = message_info.getRequest()
        if service is None or request is None:
            return
        if len(self.roles) >= _ROLE_LIMIT:
            self.status_label.setText("Role limit reached (%d)." % _ROLE_LIMIT)
            return
        try:
            request_info = self.helpers.analyzeRequest(service, request)
            origin = "%s://%s:%d" % (
                service.getProtocol(), service.getHost(), int(service.getPort())
            )
            headers = self._present_identity_headers(service, request)
            default_name = "State %d" % (len(self.roles) + 1)
            name = JOptionPane.showInputDialog(
                self.panel, "User/state label:", default_name
            )
            if name is None or not str(name).strip():
                return
            name = str(name).strip()
            existing_index = self._role_index(name)
            if existing_index >= 0:
                answer = JOptionPane.showConfirmDialog(
                    self.panel,
                    "Replace the captured request for '%s'?" % name,
                    "Replace captured state",
                    JOptionPane.YES_NO_OPTION,
                )
                if answer != JOptionPane.YES_OPTION:
                    return
                self.roles.pop(existing_index)
            self.roles.append(
                {
                    "name": name,
                    "origin": origin,
                    "service": service,
                    "request": request,
                    "method": str(request_info.getMethod()).upper(),
                    "captured_headers": headers or "None of the configured headers",
                }
            )
            self._refresh_roles()
            self.status_label.setText("Captured '%s' in memory for this Burp session." % name)
        except Exception as error:
            self.status_label.setText("Could not capture role: " + str(error))

    def _role_index(self, name):
        for index, role in enumerate(self.roles):
            if role["name"].lower() == name.lower():
                return index
        return -1

    def _present_identity_headers(self, service, request):
        names = _parse_identity_headers(self.identity_headers.getText())
        request_info = self.helpers.analyzeRequest(service, request)
        found = []
        for header in request_info.getHeaders()[1:]:
            name = _header_name(str(header))
            if name in [candidate.lower() for candidate in names]:
                found.append(name)
        return ", ".join(sorted(set(found)))

    def _remove_selected_roles(self):
        if self.running:
            return
        selected = self.role_table.getSelectedRows()
        if not selected:
            return
        indices = sorted(
            [self.role_table.convertRowIndexToModel(row) for row in selected],
            reverse=True,
        )
        for index in indices:
            if index < len(self.roles):
                del self.roles[index]
        self._refresh_roles()

    def _selected_roles(self):
        rows = self.role_table.getSelectedRows()
        selected = []
        for row in rows:
            model_row = self.role_table.convertRowIndexToModel(row)
            if model_row < len(self.displayed_roles):
                role_name = self.displayed_roles[model_row]
                index = self._role_index(role_name)
                if index >= 0:
                    selected.append(self.roles[index])
        return selected

    def _compare_selected_roles(self):
        if self.running:
            return
        if self.target is None:
            self.status_label.setText("Load a target request first.")
            return
        selected = self._selected_roles()
        if len(selected) < 2:
            self.status_label.setText("Select at least two captured users/states.")
            return
        if len(selected) > _MAX_SELECTED_ROLES:
            self.status_label.setText(
                "Select no more than %d users/states per comparison."
                % _MAX_SELECTED_ROLES
            )
            return
        headers = _parse_identity_headers(self.identity_headers.getText())
        if not headers:
            self.status_label.setText("Enter at least one valid identity header name.")
            return
        try:
            rounds = int(self.rounds_field.getText().strip())
            if not 1 <= rounds <= _MAX_ROUNDS:
                raise ValueError("Rounds must be between 1 and %d." % _MAX_ROUNDS)
        except Exception as error:
            self.status_label.setText(str(error))
            return
        if not self.callbacks.isInScope(URL(self.target["url"])):
            self.status_label.setText("Replay blocked: target is outside Burp scope.")
            return
        for role in selected:
            if not self._same_origin(self.target["service"], role["service"]):
                self.status_label.setText(
                    "Captured states must use the same scheme, host, and port as the target."
                )
                return
        if self.target["method"] not in ("GET", "HEAD"):
            if not self.allow_unsafe_box.isSelected():
                self.status_label.setText(
                    "Non-GET/HEAD replay is blocked. Enable the override only if replay is safe."
                )
                return
            answer = JOptionPane.showConfirmDialog(
                self.panel,
                "This request may change application state and will be replayed %d times per selected role. Continue?"
                % rounds,
                "Confirm non-idempotent replay",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
            if answer != JOptionPane.YES_OPTION:
                return

        target = dict(self.target)
        roles = [dict(role) for role in selected]
        self.running = True
        self._set_controls_enabled(False)
        self.status_label.setText(
            "Comparing %d states over %d round(s)..." % (len(roles), rounds)
        )
        extension = self

        class CompareWorker(SwingWorker):
            def doInBackground(worker_self):
                return extension._compare(target, roles, headers, rounds)

            def done(worker_self):
                extension.running = False
                extension._set_controls_enabled(True)
                try:
                    result_rows = worker_self.get()
                    extension._show_results(result_rows)
                    extension.status_label.setText(
                        "Completed %d pairwise comparison(s). Results are differential indicators, not proof of browser exploitability."
                        % len(result_rows)
                    )
                except Exception as error:
                    extension.status_label.setText("Comparison failed: " + str(error))

        CompareWorker().execute()

    def _set_controls_enabled(self, enabled):
        self.set_target_button.setEnabled(enabled)
        self.compare_button.setEnabled(enabled)
        self.remove_role_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)
        self.identity_headers.setEnabled(enabled)
        self.rounds_field.setEnabled(enabled)
        self.allow_unsafe_box.setEnabled(enabled)

    def _same_origin(self, first_service, second_service):
        return (
            str(first_service.getProtocol()).lower()
            == str(second_service.getProtocol()).lower()
            and str(first_service.getHost()).lower()
            == str(second_service.getHost()).lower()
            and int(first_service.getPort()) == int(second_service.getPort())
        )

    def _replace_identity_headers(self, target, role, names):
        target_info = self.helpers.analyzeRequest(
            target["service"], target["request"]
        )
        role_info = self.helpers.analyzeRequest(role["service"], role["request"])
        target_headers = [str(header) for header in target_info.getHeaders()]
        role_headers = [str(header) for header in role_info.getHeaders()[1:]]
        normalized_names = set([name.lower() for name in names])

        filtered_headers = [target_headers[0]]
        for header in target_headers[1:]:
            if _header_name(header) not in normalized_names:
                filtered_headers.append(header)
        for name in names:
            for header in role_headers:
                if _header_name(header) == name.lower():
                    filtered_headers.append(header)

        java_headers = ArrayList()
        for header in filtered_headers:
            java_headers.add(header)
        body = target["request"][int(target_info.getBodyOffset()):]
        return self.helpers.buildHttpMessage(java_headers, body)

    def _compare(self, target, roles, headers, rounds):
        samples = dict((role["name"], []) for role in roles)
        errors = dict((role["name"], []) for role in roles)
        for round_index in range(rounds):
            offset = round_index % len(roles)
            order = roles[offset:] + roles[:offset]
            for role in order:
                try:
                    if not self.callbacks.isInScope(URL(target["url"])):
                        errors[role["name"]].append("Target left Burp scope.")
                        continue
                    request = self._replace_identity_headers(target, role, headers)
                    started = System.nanoTime()
                    exchange = self.callbacks.makeHttpRequest(
                        target["service"], request
                    )
                    elapsed_ms = (System.nanoTime() - started) / 1000000.0
                    response = exchange.getResponse() if exchange is not None else None
                    if response is None:
                        errors[role["name"]].append("No HTTP response.")
                        continue
                    samples[role["name"]].append(
                        _response_metrics(self.helpers, response, elapsed_ms)
                    )
                except Exception as error:
                    errors[role["name"]].append(str(error))

        aggregates = {}
        for role in roles:
            if samples[role["name"]]:
                aggregates[role["name"]] = _aggregate_samples(samples[role["name"]])

        result_rows = []
        for first_index in range(len(roles)):
            for second_index in range(first_index + 1, len(roles)):
                first_role = roles[first_index]
                second_role = roles[second_index]
                first_name = first_role["name"]
                second_name = second_role["name"]
                first = aggregates.get(first_name)
                second = aggregates.get(second_name)
                if first is None or second is None:
                    signals = ["insufficient response samples"]
                    timing_delta = 0.0
                    assessment = "Inconclusive"
                else:
                    signals, timing_delta = _compare_metrics(first, second)
                    assessment = (
                        "Potential XS-Leak oracle"
                        if signals
                        else "No difference observed"
                    )
                    if errors[first_name] or errors[second_name]:
                        assessment = "Partial results"

                details = self._format_pair_details(
                    first_name,
                    second_name,
                    first,
                    second,
                    signals,
                    errors[first_name],
                    errors[second_name],
                )
                result_rows.append(
                    {
                        "target": target["url"],
                        "roles": "%s vs %s" % (first_name, second_name),
                        "signals": ", ".join(signals) if signals else "None",
                        "delta_ms": "%.0f" % timing_delta,
                        "assessment": assessment,
                        "details": details,
                    }
                )
        return result_rows

    def _format_pair_details(
        self, first_name, second_name, first, second, signals, first_errors, second_errors
    ):
        lines = ["Differential XS-Leak oracle check", ""]
        for name, result in ((first_name, first), (second_name, second)):
            lines.append("State: " + name)
            if result is None:
                lines.append("  No successful response samples.")
                continue
            lines.append("  HTTP status: %s" % result["status"])
            lines.append("  Response body length: %.0f bytes" % result["body_length"])
            lines.append("  Median response time: %.1f ms" % result["time_ms"])
            lines.append("  Redirect behavior: " + result["redirect"])
            for header in _DIFF_HEADERS:
                lines.append("  %s: %s" % (header, result["headers"][header]))
        lines.append("")
        lines.append("Differing signals: " + (", ".join(signals) if signals else "none observed"))
        if first_errors:
            lines.append("%s errors: %s" % (first_name, "; ".join(first_errors)))
        if second_errors:
            lines.append("%s errors: %s" % (second_name, "; ".join(second_errors)))
        lines.append("")
        lines.append(
            "A differential is a candidate side channel. Confirm it in a browser with a cross-site attacker-controlled page."
        )
        return "\n".join(lines)

    def _show_results(self, rows):
        self.results = rows
        self.result_model.setRowCount(0)
        for row in rows:
            self.result_model.addRow(
                [
                    row["target"],
                    row["roles"],
                    row["signals"],
                    row["delta_ms"],
                    row["assessment"],
                ]
            )
        self.result_details.setText("")

    def _show_selected_result(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.result_table.getSelectedRow()
        if row < 0:
            self.result_details.setText("")
            return
        model_row = self.result_table.convertRowIndexToModel(row)
        if model_row < len(self.results):
            self.result_details.setText(self.results[model_row]["details"])

    def _clear_results(self):
        if self.running:
            return
        self.results = []
        self.result_model.setRowCount(0)
        self.result_details.setText("")
        self.status_label.setText("Differential results cleared.")