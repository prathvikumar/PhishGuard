
import sys
import json
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
from tkinter import filedialog, messagebox


# --------------------------------------------------
# PATHS AND EXISTING PROJECT MODULES
# --------------------------------------------------

SRC_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SRC_DIR.parent
REPORTS_DIR = PROJECT_DIR / "reports"

REPORTS_DIR.mkdir(exist_ok=True)

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from email_analyzer import analyze_email
from phishing_detector import analyze_phishing


# --------------------------------------------------
# THEME
# --------------------------------------------------

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#0B1020"
SIDEBAR = "#0F172A"
PANEL = "#151D32"
PANEL_HOVER = "#202B45"
BORDER = "#293550"
VIOLET = "#8B5CF6"
VIOLET_HOVER = "#7C3AED"
TEXT = "#F1F5F9"
MUTED = "#94A3B8"
GREEN = "#34D399"
YELLOW = "#FBBF24"
RED = "#FB7185"
CYAN = "#67E8F9"


class PhishGuardGUI(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("PhishGuard Lite | Security Dashboard")
        self.geometry("1250x800")
        self.minsize(1000, 650)
        self.configure(fg_color=BG)

        self.selected_file = None
        self.last_report = None
        self.history = []
        self.current_page = "Dashboard"
        self.nav_buttons = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.content = ctk.CTkFrame(
            self,
            fg_color=BG,
            corner_radius=0
        )
        self.content.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(0, 20),
            pady=18
        )
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self.show_dashboard()

    # --------------------------------------------------
    # SIDEBAR
    # --------------------------------------------------

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self,
            width=235,
            fg_color=SIDEBAR,
            corner_radius=0
        )
        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew"
        )
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(7, weight=1)

        brand = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )
        brand.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=20,
            pady=(28, 34)
        )

        ctk.CTkLabel(
            brand,
            text="⬡",
            font=ctk.CTkFont(size=34, weight="bold"),
            text_color=VIOLET
        ).pack(side="left", padx=(0, 10))

        brand_text = ctk.CTkFrame(
            brand,
            fg_color="transparent"
        )
        brand_text.pack(side="left")

        ctk.CTkLabel(
            brand_text,
            text="PHISHGUARD",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=TEXT
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand_text,
            text="L I T E",
            font=ctk.CTkFont(size=10),
            text_color=MUTED
        ).pack(anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text="WORKSPACE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=MUTED,
            anchor="w"
        ).grid(
            row=1,
            column=0,
            sticky="ew",
            padx=22,
            pady=(0, 10)
        )

        navigation = [
            ("Dashboard", "⌂"),
            ("Scan Email", "◎"),
            ("Scan History", "◷"),
            ("Reports", "▤"),
            ("Settings", "⚙"),
        ]

        for index, (name, symbol) in enumerate(navigation, start=2):
            button = ctk.CTkButton(
                self.sidebar,
                text=f"   {symbol}     {name}",
                anchor="w",
                height=43,
                corner_radius=9,
                fg_color="transparent",
                hover_color=PANEL_HOVER,
                text_color=MUTED,
                font=ctk.CTkFont(size=13),
                command=lambda page=name: self.navigate(page)
            )
            button.grid(
                row=index,
                column=0,
                sticky="ew",
                padx=12,
                pady=3
            )
            self.nav_buttons[name] = button

        # Sidebar footer
        footer = ctk.CTkFrame(
            self.sidebar,
            fg_color=PANEL,
            corner_radius=12
        )
        footer.grid(
            row=8,
            column=0,
            sticky="ew",
            padx=12,
            pady=16
        )

        ctk.CTkLabel(
            footer,
            text="●  LOCAL ANALYSIS",
            text_color=GREEN,
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(anchor="w", padx=13, pady=(13, 4))

        ctk.CTkLabel(
            footer,
            text="Email files are analyzed\non this computer.",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            justify="left"
        ).pack(anchor="w", padx=13, pady=(0, 13))

        ctk.CTkLabel(
            self.sidebar,
            text="PHISHGUARD LITE  •  v1.0",
            text_color="#64748B",
            font=ctk.CTkFont(size=10)
        ).grid(
            row=9,
            column=0,
            sticky="ew",
            padx=16,
            pady=(0, 16)
        )

    def _set_active_nav(self, page):
        self.current_page = page

        for name, button in self.nav_buttons.items():
            if name == page:
                button.configure(
                    fg_color="#2B2150",
                    hover_color="#35265F",
                    text_color="#C4B5FD"
                )
            else:
                button.configure(
                    fg_color="transparent",
                    hover_color=PANEL_HOVER,
                    text_color=MUTED
                )

    def navigate(self, page):
        self._set_active_nav(page)

        if page == "Dashboard":
            self.show_dashboard()
        elif page == "Scan Email":
            self.show_scanner()
        elif page == "Scan History":
            self.show_history()
        elif page == "Reports":
            self.show_reports()
        elif page == "Settings":
            self.show_settings()

    # --------------------------------------------------
    # COMMON PAGE COMPONENTS
    # --------------------------------------------------

    def _clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def _page_header(self, title, subtitle):
        header = ctk.CTkFrame(
            self.content,
            fg_color="transparent"
        )
        header.grid(
            row=0,
            column=0,
            sticky="ew",
            pady=(0, 22)
        )
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text=title,
            font=ctk.CTkFont(size=27, weight="bold"),
            text_color=TEXT,
            anchor="w"
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text=subtitle,
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="w"
        ).grid(row=1, column=0, sticky="w", pady=(5, 0))

        ctk.CTkLabel(
            header,
            text="●  SYSTEM READY",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=GREEN
        ).grid(row=0, column=1, rowspan=2, padx=10)

    def _new_page(self, title, subtitle):
        self._clear_content()
        self._page_header(title, subtitle)

        page = ctk.CTkScrollableFrame(
            self.content,
            fg_color="transparent",
            corner_radius=0
        )
        page.grid(
            row=1,
            column=0,
            sticky="nsew"
        )
        page.grid_columnconfigure(0, weight=1)

        return page

    def _card(self, parent, title, value, note, accent=VIOLET):
        card = ctk.CTkFrame(
            parent,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )

        ctk.CTkFrame(
            card,
            width=4,
            height=48,
            fg_color=accent,
            corner_radius=3
        ).pack(
            side="left",
            padx=(14, 12),
            pady=16
        )

        info = ctk.CTkFrame(
            card,
            fg_color="transparent"
        )
        info.pack(
            side="left",
            fill="both",
            expand=True,
            pady=15,
            padx=(0, 10)
        )

        ctk.CTkLabel(
            info,
            text=title,
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            anchor="w"
        ).pack(anchor="w")

        ctk.CTkLabel(
            info,
            text=str(value),
            text_color=TEXT,
            font=ctk.CTkFont(size=25, weight="bold"),
            anchor="w"
        ).pack(anchor="w", pady=(3, 2))

        ctk.CTkLabel(
            info,
            text=note,
            text_color=accent,
            font=ctk.CTkFont(size=10),
            anchor="w"
        ).pack(anchor="w")

        return card

    def _section_title(self, parent, title, subtitle=None):
        ctk.CTkLabel(
            parent,
            text=title,
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        ).pack(anchor="w", pady=(0, 5))

        if subtitle:
            ctk.CTkLabel(
                parent,
                text=subtitle,
                text_color=MUTED,
                font=ctk.CTkFont(size=11),
                anchor="w"
            ).pack(anchor="w", pady=(0, 12))

    # --------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------

    def show_dashboard(self):
        self._set_active_nav("Dashboard")

        page = self._new_page(
            "Security Dashboard",
            "Monitor email scans and review phishing indicators."
        )

        # Welcome banner
        welcome = ctk.CTkFrame(
            page,
            fg_color="#1C2140",
            corner_radius=16,
            border_width=1,
            border_color="#393365"
        )
        welcome.grid(
            row=0,
            column=0,
            sticky="ew",
            pady=(0, 20)
        )
        welcome.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            welcome,
            text="Stay one step ahead of phishing.",
            text_color=TEXT,
            font=ctk.CTkFont(size=21, weight="bold"),
            anchor="w"
        ).grid(
            row=0,
            column=0,
            padx=22,
            pady=(22, 6),
            sticky="w"
        )

        ctk.CTkLabel(
            welcome,
            text="Analyze .eml files and inspect suspicious wording and URLs.",
            text_color="#C4B5FD",
            font=ctk.CTkFont(size=12),
            anchor="w",
            wraplength=550
        ).grid(
            row=1,
            column=0,
            padx=22,
            pady=(0, 16),
            sticky="w"
        )

        ctk.CTkButton(
            welcome,
            text="＋   Scan an Email",
            width=155,
            height=40,
            corner_radius=9,
            fg_color=VIOLET,
            hover_color=VIOLET_HOVER,
            command=lambda: self.navigate("Scan Email")
        ).grid(
            row=2,
            column=0,
            padx=22,
            pady=(0, 22),
            sticky="w"
        )

        # Statistics cards
        stats = ctk.CTkFrame(
            page,
            fg_color="transparent"
        )
        stats.grid(
            row=1,
            column=0,
            sticky="ew",
            pady=(0, 24)
        )

        for col in range(3):
            stats.grid_columnconfigure(col, weight=1, uniform="stats")

        total = len(self.history)
        high = sum(1 for item in self.history if item["risk_level"] == "High")
        medium = sum(1 for item in self.history if item["risk_level"] == "Medium")

        cards = [
            ("TOTAL SCANS", total, "Scans this session", VIOLET),
            ("HIGH RISK", high, "High-risk results", RED),
            ("MEDIUM RISK", medium, "Medium-risk results", YELLOW),
        ]

        for col, data in enumerate(cards):
            title, value, note, accent = data
            card = self._card(stats, title, value, note, accent)
            card.grid(
                row=0,
                column=col,
                sticky="nsew",
                padx=(0 if col == 0 else 7, 7 if col < 2 else 0)
            )

        # Recent scans
        recent = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        recent.grid(
            row=2,
            column=0,
            sticky="ew",
            pady=(0, 18)
        )

        ctk.CTkLabel(
            recent,
            text="Recent Scans",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=18, pady=(17, 3))

        ctk.CTkLabel(
            recent,
            text="Latest email analyses in this session",
            text_color=MUTED,
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=18, pady=(0, 12))

        if not self.history:
            ctk.CTkLabel(
                recent,
                text="No scans yet. Start by analyzing an email file.",
                text_color=MUTED,
                font=ctk.CTkFont(size=12)
            ).pack(anchor="w", padx=18, pady=(8, 22))
        else:
            for item in reversed(self.history[-5:]):
                row = ctk.CTkFrame(
                    recent,
                    fg_color="#10182A",
                    corner_radius=9
                )
                row.pack(
                    fill="x",
                    padx=14,
                    pady=4
                )

                color = self._risk_color(item["risk_level"])

                ctk.CTkLabel(
                    row,
                    text=item["file"],
                    text_color=TEXT,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    anchor="w"
                ).pack(side="left", padx=12, pady=13)

                ctk.CTkLabel(
                    row,
                    text=f'{item["risk_level"]}  ·  {item["risk_score"]}/10',
                    text_color=color,
                    font=ctk.CTkFont(size=11, weight="bold")
                ).pack(side="right", padx=12, pady=13)

            ctk.CTkButton(
                recent,
                text="View Scan History →",
                fg_color="transparent",
                hover_color=PANEL_HOVER,
                text_color="#C4B5FD",
                command=lambda: self.navigate("Scan History")
            ).pack(anchor="e", padx=14, pady=10)

        ctk.CTkLabel(
            page,
            text="Note: A low score does not guarantee an email is safe.",
            text_color=MUTED,
            font=ctk.CTkFont(size=11)
        ).grid(row=3, column=0, sticky="w", pady=(0, 12))

    # --------------------------------------------------
    # EMAIL SCANNER
    # --------------------------------------------------

    def show_scanner(self):
        self._set_active_nav("Scan Email")

        page = self._new_page(
            "Email Scanner",
            "Choose an email file to analyze locally."
        )

        # File selection panel
        upload = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=15,
            border_width=1,
            border_color=BORDER
        )
        upload.grid(
            row=0,
            column=0,
            sticky="ew",
            pady=(0, 18)
        )

        ctk.CTkLabel(
            upload,
            text="SELECT EMAIL FILE",
            text_color=MUTED,
            font=ctk.CTkFont(size=10, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 7))

        ctk.CTkLabel(
            upload,
            text="Choose an .eml file from your computer",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(0, 5))

        ctk.CTkLabel(
            upload,
            text="Your existing analysis engine will inspect the email content.",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            wraplength=650
        ).pack(anchor="w", padx=20, pady=(0, 15))

        self.file_label = ctk.CTkLabel(
            upload,
            text=(
                str(self.selected_file)
                if self.selected_file
                else "No file selected"
            ),
            text_color="#C4B5FD",
            font=ctk.CTkFont(size=11),
            anchor="w",
            wraplength=700
        )
        self.file_label.pack(fill="x", padx=20, pady=(0, 15))

        buttons = ctk.CTkFrame(
            upload,
            fg_color="transparent"
        )
        buttons.pack(anchor="w", padx=20, pady=(0, 20))

        ctk.CTkButton(
            buttons,
            text="Choose Email",
            width=140,
            height=39,
            fg_color="#28334D",
            hover_color="#364563",
            command=self.choose_file
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            buttons,
            text="▶   Analyze Email",
            width=160,
            height=39,
            fg_color=VIOLET,
            hover_color=VIOLET_HOVER,
            command=self.scan_email
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            buttons,
            text="Save JSON Report",
            width=150,
            height=39,
            fg_color="#28334D",
            hover_color="#364563",
            command=self.save_report
        ).pack(side="left")

        # Results panel
        self.results_panel = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=15,
            border_width=1,
            border_color=BORDER
        )
        self.results_panel.grid(
            row=1,
            column=0,
            sticky="ew"
        )
        self.results_panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.results_panel,
            text="ANALYSIS RESULTS",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(
            row=0,
            column=0,
            padx=20,
            pady=(18, 12),
            sticky="w"
        )

        self.result_summary = ctk.CTkFrame(
            self.results_panel,
            fg_color="transparent"
        )
        self.result_summary.grid(
            row=1,
            column=0,
            padx=16,
            pady=(0, 14),
            sticky="ew"
        )

        self._empty_result()

    def _empty_result(self):
        for widget in self.result_summary.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self.result_summary,
            text="◎",
            text_color=VIOLET,
            font=ctk.CTkFont(size=40)
        ).pack(pady=(18, 5))

        ctk.CTkLabel(
            self.result_summary,
            text="Waiting for an email to analyze",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(0, 5))

        ctk.CTkLabel(
            self.result_summary,
            text="Your risk score and findings will appear here.",
            text_color=MUTED,
            font=ctk.CTkFont(size=12)
        ).pack(pady=(0, 22))

    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Select an email file",
            filetypes=[
                ("Email files", "*.eml"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.selected_file = Path(path)
            self.last_report = None

            if hasattr(self, "file_label"):
                self.file_label.configure(text=str(self.selected_file))

            if hasattr(self, "result_summary"):
                self._empty_result()

    def scan_email(self):
        if not self.selected_file:
            messagebox.showwarning(
                "No email selected",
                "Choose an .eml file before scanning."
            )
            return

        try:
            email_data = analyze_email(self.selected_file)
            detection = analyze_phishing(email_data)

            score = detection["risk_score"]
            risk = detection["risk_level"]
            findings = detection["findings"]
            urls = detection["urls_found"]

            report = {
                "file": self.selected_file.name,
                "analyzed_at": datetime.now().isoformat(timespec="seconds"),
                "email": email_data,
                "risk_score": score,
                "risk_level": risk,
                "findings": findings,
                "urls_found": urls,
            }

            self.last_report = report

            self.history.append({
                "file": self.selected_file.name,
                "analyzed_at": report["analyzed_at"],
                "risk_score": score,
                "risk_level": risk,
                "report": report
            })

            self._display_result(email_data, detection)

        except Exception as exc:
            messagebox.showerror(
                "Analysis Error",
                f"Could not analyze this email:\n\n{exc}"
            )

    def _risk_color(self, risk):
        if risk == "High":
            return RED
        if risk == "Medium":
            return YELLOW
        return GREEN

    def _display_result(self, email_data, detection):
        for widget in self.result_summary.winfo_children():
            widget.destroy()

        score = detection["risk_score"]
        risk = detection["risk_level"]
        findings = detection["findings"]
        urls = detection["urls_found"]
        accent = self._risk_color(risk)

        # Risk overview
        overview = ctk.CTkFrame(
            self.result_summary,
            fg_color="#10182A",
            corner_radius=12
        )
        overview.pack(fill="x", pady=(0, 14))
        overview.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            overview,
            text="RISK ASSESSMENT",
            text_color=MUTED,
            font=ctk.CTkFont(size=10, weight="bold")
        ).grid(
            row=0,
            column=0,
            padx=18,
            pady=(16, 4),
            sticky="w"
        )

        ctk.CTkLabel(
            overview,
            text=f"{score}/10",
            text_color=accent,
            font=ctk.CTkFont(size=38, weight="bold")
        ).grid(
            row=1,
            column=0,
            padx=18,
            pady=(0, 2),
            sticky="w"
        )

        ctk.CTkLabel(
            overview,
            text=f"{risk.upper()} RISK",
            text_color=accent,
            font=ctk.CTkFont(size=12, weight="bold")
        ).grid(
            row=2,
            column=0,
            padx=18,
            pady=(0, 12),
            sticky="w"
        )

        progress = ctk.CTkProgressBar(
            overview,
            height=9,
            progress_color=accent,
            fg_color="#293550"
        )
        progress.grid(
            row=3,
            column=0,
            padx=18,
            pady=(0, 17),
            sticky="ew"
        )
        progress.set(score / 10)

        # Email details
        details = ctk.CTkFrame(
            self.result_summary,
            fg_color="#10182A",
            corner_radius=12
        )
        details.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            details,
            text="EMAIL DETAILS",
            text_color=MUTED,
            font=ctk.CTkFont(size=10, weight="bold")
        ).pack(anchor="w", padx=16, pady=(14, 7))

        detail_values = [
            ("SUBJECT", email_data.get("subject") or "(No subject)"),
            ("SENDER", email_data.get("sender") or "(Unknown sender)"),
            ("RECIPIENT", email_data.get("recipient") or "(Not provided)"),
        ]

        for label, value in detail_values:
            line = ctk.CTkFrame(
                details,
                fg_color="transparent"
            )
            line.pack(fill="x", padx=16, pady=4)

            ctk.CTkLabel(
                line,
                text=label,
                width=85,
                anchor="w",
                text_color=MUTED,
                font=ctk.CTkFont(size=10, weight="bold")
            ).pack(side="left")

            ctk.CTkLabel(
                line,
                text=value,
                anchor="w",
                justify="left",
                wraplength=650,
                text_color=TEXT,
                font=ctk.CTkFont(size=11)
            ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            details,
            text=f"{len(findings)} indicators  ·  {len(urls)} URLs found",
            text_color="#C4B5FD",
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(anchor="w", padx=16, pady=(8, 14))

        # Findings
        findings_frame = ctk.CTkFrame(
            self.result_summary,
            fg_color="#10182A",
            corner_radius=12
        )
        findings_frame.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            findings_frame,
            text="DETECTION FINDINGS",
            text_color=TEXT,
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=16, pady=(15, 10))

        if findings:
            for finding in findings:
                item = ctk.CTkFrame(
                    findings_frame,
                    fg_color=PANEL,
                    corner_radius=9
                )
                item.pack(fill="x", padx=12, pady=4)

                ctk.CTkLabel(
                    item,
                    text=f"+{finding['points']}",
                    width=48,
                    text_color=accent,
                    font=ctk.CTkFont(size=13, weight="bold")
                ).pack(side="left", padx=(8, 4), pady=10)

                description = ctk.CTkFrame(
                    item,
                    fg_color="transparent"
                )
                description.pack(
                    side="left",
                    fill="x",
                    expand=True,
                    padx=4,
                    pady=8
                )

                ctk.CTkLabel(
                    description,
                    text=finding["indicator"],
                    text_color=TEXT,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    anchor="w"
                ).pack(anchor="w")

                ctk.CTkLabel(
                    description,
                    text=finding["details"],
                    text_color=MUTED,
                    font=ctk.CTkFont(size=10),
                    anchor="w",
                    justify="left",
                    wraplength=650
                ).pack(anchor="w", pady=(3, 0))
        else:
            ctk.CTkLabel(
                findings_frame,
                text="✓  No configured phishing indicators were detected.",
                text_color=GREEN,
                font=ctk.CTkFont(size=12)
            ).pack(anchor="w", padx=16, pady=(0, 16))

        # URL list
        urls_frame = ctk.CTkFrame(
            self.result_summary,
            fg_color="#10182A",
            corner_radius=12
        )
        urls_frame.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            urls_frame,
            text="URLS FOUND",
            text_color=TEXT,
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=16, pady=(15, 10))

        if urls:
            for url in urls:
                ctk.CTkLabel(
                    urls_frame,
                    text=f"↗  {url}",
                    text_color=CYAN,
                    font=ctk.CTkFont(size=11),
                    anchor="w",
                    wraplength=750
                ).pack(anchor="w", padx=16, pady=4)
        else:
            ctk.CTkLabel(
                urls_frame,
                text="No URLs found.",
                text_color=MUTED,
                font=ctk.CTkFont(size=11)
            ).pack(anchor="w", padx=16, pady=(0, 15))

        ctk.CTkLabel(
            self.result_summary,
            text=(
                "Safety note: this is a basic heuristic analysis. "
                "A low score does not guarantee an email is safe. "
                "URLs are displayed, never opened."
            ),
            text_color=MUTED,
            font=ctk.CTkFont(size=10),
            wraplength=750,
            justify="left"
        ).pack(anchor="w", pady=(2, 16))

    # --------------------------------------------------
    # SCAN HISTORY
    # --------------------------------------------------

    def show_history(self):
        self._set_active_nav("Scan History")

        page = self._new_page(
            "Scan History",
            "Review emails analyzed during the current application session."
        )

        panel = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        panel.grid(row=0, column=0, sticky="ew")

        if not self.history:
            ctk.CTkLabel(
                panel,
                text="No scan history yet.",
                text_color=TEXT,
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(anchor="w", padx=20, pady=(24, 5))

            ctk.CTkLabel(
                panel,
                text="Scans will appear here after you analyze emails.",
                text_color=MUTED,
                font=ctk.CTkFont(size=12)
            ).pack(anchor="w", padx=20, pady=(0, 24))
            return

        for item in reversed(self.history):
            row = ctk.CTkFrame(
                panel,
                fg_color="#10182A",
                corner_radius=10
            )
            row.pack(fill="x", padx=14, pady=6)

            color = self._risk_color(item["risk_level"])

            ctk.CTkLabel(
                row,
                text=item["file"],
                text_color=TEXT,
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w"
            ).pack(anchor="w", padx=14, pady=(12, 4))

            ctk.CTkLabel(
                row,
                text=(
                    f'{item["analyzed_at"]}    ·    '
                    f'{item["risk_level"]} risk    ·    '
                    f'{item["risk_score"]}/10'
                ),
                text_color=color,
                font=ctk.CTkFont(size=11),
                anchor="w"
            ).pack(anchor="w", padx=14, pady=(0, 12))

            ctk.CTkButton(
                row,
                text="View Report",
                width=110,
                height=30,
                fg_color="#28334D",
                hover_color="#364563",
                command=lambda data=item["report"]: self.view_history_report(data)
            ).pack(anchor="e", padx=12, pady=(0, 10))

    def view_history_report(self, report):
        self.last_report = report
        self.selected_file = Path(report["file"])
        self.navigate("Scan Email")

        # Restore the report in the scanner without rescanning.
        email_data = report["email"]
        detection = {
            "risk_score": report["risk_score"],
            "risk_level": report["risk_level"],
            "findings": report["findings"],
            "urls_found": report["urls_found"],
        }

        self._display_result(email_data, detection)

        self.file_label.configure(
            text=f"Previously scanned: {report['file']}"
        )

    # --------------------------------------------------
    # REPORTS
    # --------------------------------------------------

    def show_reports(self):
        self._set_active_nav("Reports")

        page = self._new_page(
            "Reports",
            "Export the results of your latest email analysis."
        )

        panel = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        panel.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(
            panel,
            text="JSON ANALYSIS REPORT",
            text_color=VIOLET,
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(anchor="w", padx=22, pady=(22, 8))

        ctk.CTkLabel(
            panel,
            text="Export your scan findings",
            text_color=TEXT,
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", padx=22, pady=(0, 6))

        ctk.CTkLabel(
            panel,
            text=(
                "Save the latest scan as a JSON file containing email details, "
                "risk score, findings, URLs, and analysis timestamp."
            ),
            text_color=MUTED,
            font=ctk.CTkFont(size=12),
            wraplength=650,
            justify="left"
        ).pack(anchor="w", padx=22, pady=(0, 18))

        status = (
            f"Latest report: {self.last_report['file']}"
            if self.last_report
            else "No scan report available yet. Analyze an email first."
        )

        ctk.CTkLabel(
            panel,
            text=status,
            text_color=TEXT if self.last_report else MUTED,
            font=ctk.CTkFont(size=12),
            wraplength=650,
            justify="left"
        ).pack(anchor="w", padx=22, pady=(0, 18))

        ctk.CTkButton(
            panel,
            text="Save JSON Report",
            width=180,
            height=40,
            fg_color=VIOLET,
            hover_color=VIOLET_HOVER,
            command=self.save_report
        ).pack(anchor="w", padx=22, pady=(0, 22))

    def save_report(self):
        if not self.last_report:
            messagebox.showwarning(
                "No report available",
                "Scan an email before saving a report."
            )
            return

        default_name = (
            f"phishguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        path = filedialog.asksaveasfilename(
            title="Save PhishGuard JSON Report",
            defaultextension=".json",
            initialdir=str(REPORTS_DIR),
            initialfile=default_name,
            filetypes=[("JSON report", "*.json")]
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as file:
                json.dump(
                    self.last_report,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            messagebox.showinfo(
                "Report Saved",
                f"JSON report saved successfully:\n{path}"
            )
        except OSError as exc:
            messagebox.showerror(
                "Save Error",
                f"Could not save the report:\n{exc}"
            )

    # --------------------------------------------------
    # SETTINGS
    # --------------------------------------------------

    def show_settings(self):
        self._set_active_nav("Settings")

        page = self._new_page(
            "Settings",
            "Application preferences and project information."
        )

        appearance = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        appearance.grid(row=0, column=0, sticky="ew", pady=(0, 16))

        ctk.CTkLabel(
            appearance,
            text="APPEARANCE",
            text_color=VIOLET,
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(anchor="w", padx=20, pady=(20, 8))

        ctk.CTkLabel(
            appearance,
            text="Dark mode",
            text_color=TEXT,
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", padx=20, pady=(0, 4))

        ctk.CTkLabel(
            appearance,
            text="Midnight navy with violet accents.",
            text_color=MUTED,
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=20, pady=(0, 20))

        about = ctk.CTkFrame(
            page,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        about.grid(row=1, column=0, sticky="ew")

        ctk.CTkLabel(
            about,
            text="ABOUT PHISHGUARD LITE",
            text_color=VIOLET,
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(anchor="w", padx=20, pady=(20, 8))

        ctk.CTkLabel(
            about,
            text="Email Phishing Analysis Tool",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(0, 6))

        ctk.CTkLabel(
            about,
            text=(
                "A beginner-friendly cybersecurity project that parses email "
                "files and identifies configured phishing indicators.\n\n"
                "The detector is heuristic-based and does not guarantee "
                "that an email is safe or malicious."
            ),
            text_color=MUTED,
            font=ctk.CTkFont(size=12),
            justify="left",
            wraplength=650
        ).pack(anchor="w", padx=20, pady=(0, 20))


if __name__ == "__main__":
    app = PhishGuardGUI()
    app.mainloop()
