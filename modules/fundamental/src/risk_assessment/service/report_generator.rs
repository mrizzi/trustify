//! PDF report generator for risk assessment results.
//!
//! Produces a formatted PDF containing an executive summary, per-criterion
//! assessment details, and a risk assessment matrix using data stored in
//! the database (including enriched fields not exposed in the API response).

use crate::risk_assessment::model::ScoringResult;
use printpdf::*;

// ── Report data structures ──────────────────────────────────────────────────

/// All data needed to render a risk assessment PDF report.
pub struct ReportData {
    pub assessment_id: String,
    pub group_id: String,
    pub status: String,
    pub created_at: String,
    pub categories: Vec<ReportCategory>,
    pub scoring: Option<ScoringResult>,
    pub risk_prioritization: Option<serde_json::Value>,
}

/// Per-category data including enriched criterion details.
pub struct ReportCategory {
    pub category: String,
    pub criteria: Vec<ReportCriterion>,
}

/// Full criterion data including enriched fields from the database.
pub struct ReportCriterion {
    pub criterion: String,
    pub completeness: String,
    pub risk_level: String,
    pub score: f64,
    pub what_documented: Vec<String>,
    pub gaps: Vec<String>,
    pub impact_description: Option<String>,
    pub recommendations: Vec<ReportRecommendation>,
    pub details: Option<serde_json::Value>,
}

/// A single recommendation with action and priority.
pub struct ReportRecommendation {
    pub action: String,
    pub priority: String,
}

// ── Layout constants ────────────────────────────────────────────────────────

const PAGE_WIDTH: f32 = 210.0;
const PAGE_HEIGHT: f32 = 297.0;
const MARGIN_LEFT: f32 = 20.0;
const MARGIN_RIGHT: f32 = 20.0;
const MARGIN_TOP: f32 = 20.0;
const MARGIN_BOTTOM: f32 = 25.0;
const FONT_SIZE_TITLE: f32 = 18.0;
const FONT_SIZE_HEADING: f32 = 14.0;
const FONT_SIZE_SUBHEADING: f32 = 12.0;
const FONT_SIZE_BODY: f32 = 10.0;
const FONT_SIZE_SMALL: f32 = 8.0;

const LINE_HEIGHT_TITLE: f32 = 8.0;
const LINE_HEIGHT_HEADING: f32 = 7.0;
const LINE_HEIGHT_BODY: f32 = 5.0;
const LINE_HEIGHT_SMALL: f32 = 4.0;

/// Approximate characters per line at body font size.
const CHARS_PER_LINE: usize = 90;

// ── ReportWriter ────────────────────────────────────────────────────────────

/// Wraps `printpdf` to provide a higher-level API for writing report content.
struct ReportWriter {
    doc: PdfDocumentReference,
    font: IndirectFontRef,
    font_bold: IndirectFontRef,
    current_page: PdfPageIndex,
    current_layer: PdfLayerIndex,
    /// Current Y position in mm from the bottom of the page.
    y: f32,
}

impl ReportWriter {
    fn new(title: &str) -> Result<Self, anyhow::Error> {
        let (doc, page, layer) =
            PdfDocument::new(title, Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Layer 1");
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        Ok(Self {
            doc,
            font,
            font_bold,
            current_page: page,
            current_layer: layer,
            y: PAGE_HEIGHT - MARGIN_TOP,
        })
    }

    /// Returns a reference to the current drawing layer.
    fn layer(&self) -> PdfLayerReference {
        self.doc
            .get_page(self.current_page)
            .get_layer(self.current_layer)
    }

    /// Advance the cursor downward, adding a new page if needed.
    fn advance(&mut self, mm: f32) {
        self.y -= mm;
        if self.y < MARGIN_BOTTOM {
            self.new_page();
        }
    }

    /// Start a new page and reset the cursor.
    fn new_page(&mut self) {
        let (page, layer) = self
            .doc
            .add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Layer 1");
        self.current_page = page;
        self.current_layer = layer;
        self.y = PAGE_HEIGHT - MARGIN_TOP;
    }

    /// Ensure at least `needed` mm of space remain before the bottom margin.
    fn ensure_space(&mut self, needed: f32) {
        if self.y - needed < MARGIN_BOTTOM {
            self.new_page();
        }
    }

    // ── Text helpers ────────────────────────────────────────────────────

    fn write_text(&self, text: &str, size: f32, x: f32, font: &IndirectFontRef) {
        self.layer().use_text(text, size, Mm(x), Mm(self.y), font);
    }

    fn title(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_TITLE + 4.0);
        self.write_text(text, FONT_SIZE_TITLE, MARGIN_LEFT, &self.font_bold.clone());
        self.advance(LINE_HEIGHT_TITLE + 4.0);
    }

    fn heading(&mut self, text: &str) {
        self.ensure_space(3.0 + LINE_HEIGHT_HEADING + 2.0);
        self.advance(3.0);
        self.write_text(
            text,
            FONT_SIZE_HEADING,
            MARGIN_LEFT,
            &self.font_bold.clone(),
        );
        self.advance(LINE_HEIGHT_HEADING + 2.0);
    }

    fn subheading(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_HEADING + 2.0);
        self.advance(2.0);
        self.write_text(
            text,
            FONT_SIZE_SUBHEADING,
            MARGIN_LEFT,
            &self.font_bold.clone(),
        );
        self.advance(LINE_HEIGHT_BODY + 2.0);
    }

    fn bold_line(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_BODY);
        self.write_text(text, FONT_SIZE_BODY, MARGIN_LEFT, &self.font_bold.clone());
        self.advance(LINE_HEIGHT_BODY);
    }

    fn body(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_BODY);
        self.write_text(text, FONT_SIZE_BODY, MARGIN_LEFT, &self.font.clone());
        self.advance(LINE_HEIGHT_BODY);
    }

    fn body_at(&mut self, text: &str, x: f32) {
        self.write_text(text, FONT_SIZE_BODY, x, &self.font.clone());
    }

    fn bold_at(&mut self, text: &str, x: f32) {
        self.write_text(text, FONT_SIZE_BODY, x, &self.font_bold.clone());
    }

    /// Write a key-value line: "Key: Value".
    fn key_value(&mut self, key: &str, value: &str) {
        self.ensure_space(LINE_HEIGHT_BODY);
        self.bold_at(key, MARGIN_LEFT);
        // Offset the value roughly after the key
        let value_x = MARGIN_LEFT + (key.len() as f32 * 2.2).min(50.0);
        self.body_at(value, value_x);
        self.advance(LINE_HEIGHT_BODY);
    }

    /// Write a bullet point with indent.
    fn bullet(&mut self, text: &str) {
        let indent = MARGIN_LEFT + 5.0;
        let lines = wrap_text(text, CHARS_PER_LINE - 6);
        for (i, line) in lines.iter().enumerate() {
            self.ensure_space(LINE_HEIGHT_BODY);
            if i == 0 {
                self.write_text("•", FONT_SIZE_BODY, MARGIN_LEFT + 2.0, &self.font.clone());
            }
            self.write_text(line, FONT_SIZE_BODY, indent, &self.font.clone());
            self.advance(LINE_HEIGHT_BODY);
        }
    }

    /// Write a wrapped paragraph.
    fn paragraph(&mut self, text: &str) {
        let lines = wrap_text(text, CHARS_PER_LINE);
        for line in &lines {
            self.ensure_space(LINE_HEIGHT_BODY);
            self.write_text(line, FONT_SIZE_BODY, MARGIN_LEFT, &self.font.clone());
            self.advance(LINE_HEIGHT_BODY);
        }
    }

    fn small_text(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_SMALL);
        self.write_text(text, FONT_SIZE_SMALL, MARGIN_LEFT, &self.font.clone());
        self.advance(LINE_HEIGHT_SMALL);
    }

    fn horizontal_rule(&mut self) {
        self.ensure_space(3.0);
        self.advance(1.5);
        let layer = self.layer();
        layer.set_outline_thickness(0.5);
        let points = vec![
            (Point::new(Mm(MARGIN_LEFT), Mm(self.y)), false),
            (Point::new(Mm(PAGE_WIDTH - MARGIN_RIGHT), Mm(self.y)), false),
        ];
        layer.add_line(Line {
            points,
            is_closed: false,
        });
        self.advance(1.5);
    }

    fn spacing(&mut self, mm: f32) {
        self.advance(mm);
    }

    // ── Table helpers ───────────────────────────────────────────────────

    /// Write a table row with fixed column widths.
    fn table_row(&mut self, cells: &[&str], col_widths: &[f32], bold: bool) {
        self.ensure_space(LINE_HEIGHT_BODY);
        let font = if bold {
            self.font_bold.clone()
        } else {
            self.font.clone()
        };
        let mut x = MARGIN_LEFT;
        for (cell, &width) in cells.iter().zip(col_widths.iter()) {
            // Truncate cell text if too wide
            let max_chars = (width / 2.0) as usize;
            let display = if cell.len() > max_chars {
                &cell[..max_chars.saturating_sub(2)]
            } else {
                cell
            };
            self.write_text(display, FONT_SIZE_BODY, x, &font);
            x += width;
        }
        self.advance(LINE_HEIGHT_BODY);
    }

    /// Finalize and return PDF bytes.
    fn finish(self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(self.doc.save_to_bytes()?)
    }
}

// ── Word wrapping ───────────────────────────────────────────────────────────

/// Simple word-wrap for fixed-width approximation.
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() > max_chars {
            lines.push(current_line);
            current_line = word.to_string();
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Derive a rating label from a 0.0-1.0 score fraction.
fn rating_label(score: f64) -> &'static str {
    let pct = score * 100.0;
    if pct >= 76.0 {
        "Very High"
    } else if pct >= 51.0 {
        "High"
    } else if pct >= 26.0 {
        "Moderate"
    } else {
        "Low"
    }
}

/// Generate a PDF report from assessment data.
///
/// The report contains five sections:
///   1. Overall Rating
///   2. Criteria Summary Table
///   3. Risk Assessments (per-criterion)
///   4. Risk Prioritization
///   5. Criteria Assessments (detailed)
pub fn generate_report(data: &ReportData) -> Result<Vec<u8>, anyhow::Error> {
    let mut w = ReportWriter::new(&format!("SAR Completeness Report - {}", data.assessment_id))?;

    let (complete, partial, missing) = count_completeness(&data.categories);

    // ── Section 1: Overall Rating ──────────────────────────────────────

    w.title("SAR Completeness Report");
    w.spacing(2.0);

    w.key_value("Assessment ID:  ", &data.assessment_id);
    w.key_value("Group ID:  ", &data.group_id);
    w.key_value("Status:  ", &data.status);
    w.key_value("Date:  ", &data.created_at);
    w.spacing(2.0);

    if let Some(ref scoring) = data.scoring {
        let score_pct = scoring.overall.score * 100.0;
        w.key_value("Overall Score:  ", &format!("{:.1}%", score_pct));
        w.small_text("Calculated by LLM");
        w.spacing(1.0);
        w.key_value("Rating:  ", rating_label(scoring.overall.score));
        w.spacing(2.0);

        // Three-column counts
        let col_widths = [50.0, 50.0, 50.0];
        w.table_row(&["Complete", "Partial", "Missing"], &col_widths, true);
        w.table_row(
            &[
                &complete.to_string(),
                &partial.to_string(),
                &missing.to_string(),
            ],
            &col_widths,
            false,
        );
    } else {
        w.body("No scoring data available.");
    }

    w.spacing(3.0);
    w.horizontal_rule();

    // ── Section 2: Criteria Summary Table ──────────────────────────────

    w.heading("Criteria Summary");
    w.spacing(2.0);

    let summary_col_widths = [8.0, 55.0, 28.0, 28.0, 20.0];
    w.table_row(
        &["#", "Criterion", "Completeness", "Risk Level", "Score"],
        &summary_col_widths,
        true,
    );
    w.horizontal_rule();

    let mut criterion_number = 0usize;
    for cat in &data.categories {
        w.bold_line(&format!("Category: {}", cat.category));
        for cr in &cat.criteria {
            criterion_number += 1;
            w.table_row(
                &[
                    &criterion_number.to_string(),
                    &cr.criterion,
                    &cr.completeness,
                    &cr.risk_level,
                    &format!("{:.1}", cr.score),
                ],
                &summary_col_widths,
                false,
            );
        }
    }

    w.spacing(3.0);
    w.horizontal_rule();

    // ── Section 3: Risk Assessments (per-criterion) ────────────────────

    w.new_page();
    w.heading("Risk Assessments");
    w.spacing(2.0);

    for cat in &data.categories {
        for cr in &cat.criteria {
            if cr.completeness == "complete" {
                continue;
            }

            w.subheading(&format!(
                "{} - {} | Risk: {} ({:.1})",
                cr.criterion, cr.completeness, cr.risk_level, cr.score
            ));

            // Extract from details JSON if available
            if let Some(ref details) = cr.details {
                // Matrix reference
                if let Some(matrix_ref) = details
                    .get("risk_level")
                    .and_then(|rl| rl.get("matrix_reference"))
                    .and_then(|v| v.as_str())
                {
                    w.key_value("Matrix Reference:  ", matrix_ref);
                }

                // Likelihood
                if let Some(likelihood) = details.get("likelihood") {
                    let level = likelihood
                        .get("level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");
                    let lscore = likelihood
                        .get("score")
                        .map(format_json_value)
                        .unwrap_or_else(|| "N/A".to_string());
                    let rationale = likelihood
                        .get("rationale")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    w.bold_line("Likelihood:");
                    w.key_value("  Level:  ", level);
                    w.key_value("  Score:  ", &lscore);
                    w.key_value("  Rationale:  ", rationale);
                }

                // Impact
                if let Some(impact) = details.get("impact") {
                    let level = impact
                        .get("level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");
                    let iscore = impact
                        .get("score")
                        .map(format_json_value)
                        .unwrap_or_else(|| "N/A".to_string());
                    let rationale = impact
                        .get("rationale")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    w.bold_line("Impact:");
                    w.key_value("  Level:  ", level);
                    w.key_value("  Score:  ", &iscore);
                    w.key_value("  Rationale:  ", rationale);

                    // Impact Domains
                    if let Some(domains) = impact.get("domains") {
                        w.bold_line("  Impact Domains:");
                        for domain_name in &[
                            "availability",
                            "confidentiality",
                            "integrity",
                            "privacy",
                            "safety",
                        ] {
                            if let Some(val) = domains.get(*domain_name) {
                                w.key_value(
                                    &format!("    {}:  ", domain_name),
                                    &format_json_value(val),
                                );
                            }
                        }
                    }
                }

                // Threat Scenarios
                if let Some(scenarios) = details.get("threat_scenarios")
                    && let Some(arr) = scenarios.as_array()
                {
                    w.spacing(1.0);
                    w.bold_line("Threat Scenarios:");
                    for scenario in arr {
                        if let Some(obj) = scenario.as_object() {
                            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("N/A");
                            let source = obj
                                .get("threat_source")
                                .and_then(|v| v.as_str())
                                .unwrap_or("N/A");
                            let event = obj
                                .get("threat_event")
                                .and_then(|v| v.as_str())
                                .unwrap_or("N/A");
                            let vuln = obj
                                .get("vulnerability")
                                .and_then(|v| v.as_str())
                                .unwrap_or("N/A");
                            let attack_path = obj
                                .get("attack_path")
                                .and_then(|v| v.as_str())
                                .unwrap_or("N/A");

                            w.bullet(&format!("Name: {name}"));
                            w.body(&format!("      Source: {source}"));
                            w.body(&format!("      Event: {event}"));
                            w.body(&format!("      Vulnerability: {vuln}"));
                            w.body(&format!("      Attack Path: {attack_path}"));
                            w.spacing(1.0);
                        }
                    }
                }
            }

            w.spacing(2.0);
            w.horizontal_rule();
        }
    }

    // ── Section 4: Risk Prioritization ─────────────────────────────────

    w.new_page();
    w.heading("Risk Prioritization");
    w.spacing(2.0);

    if let Some(ref rp) = data.risk_prioritization {
        // Risk Level Summary
        if let Some(summary) = rp.get("summary") {
            w.subheading("Risk Level Summary");
            let levels = [
                ("Very High", "very_high_count"),
                ("High", "high_count"),
                ("Moderate", "moderate_count"),
                ("Low", "low_count"),
                ("Very Low", "very_low_count"),
            ];
            for (label, key) in &levels {
                let count = summary.get(*key).and_then(|v| v.as_i64()).unwrap_or(0);
                w.key_value(&format!("  {}:  ", label), &count.to_string());
            }
            w.spacing(2.0);
        }

        // Critical Gaps
        if let Some(gaps) = rp.get("critical_gaps")
            && let Some(arr) = gaps.as_array()
        {
            w.subheading("Critical Gaps");
            if arr.is_empty() {
                w.body("No critical gaps identified.");
            } else {
                let numbers: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_i64().map(|n| format!("Criterion {n}")))
                    .collect();
                w.body(&numbers.join(", "));
            }
            w.spacing(2.0);
        }

        // Top Risks
        if let Some(top_risks) = rp.get("top_risks")
            && let Some(arr) = top_risks.as_array()
        {
            w.subheading("Top Risks");
            for risk in arr {
                if let Some(obj) = risk.as_object() {
                    let rank = obj.get("rank").and_then(|v| v.as_i64()).unwrap_or(0);
                    let name = obj
                        .get("criterion_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");
                    let level = obj
                        .get("risk_level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");
                    let rscore = obj
                        .get("risk_score")
                        .map(format_json_value)
                        .unwrap_or_else(|| "N/A".to_string());
                    let gap = obj
                        .get("gap_summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");
                    let action = obj
                        .get("priority_action")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    w.bold_line(&format!("#{rank}. {name}"));
                    w.key_value("  Risk Level:  ", level);
                    w.key_value("  Score:  ", &rscore);
                    w.key_value("  Gap Summary:  ", gap);
                    w.key_value("  Priority Action:  ", action);
                    w.spacing(1.0);
                }
            }
        }
    } else {
        w.body("No risk prioritization data available.");
    }

    w.spacing(3.0);
    w.horizontal_rule();

    // ── Section 5: Criteria Assessments (detailed) ─────────────────────

    w.new_page();
    w.heading("Criteria Assessments");
    w.spacing(2.0);

    for cat in &data.categories {
        for cr in &cat.criteria {
            w.subheading(&format!("{} - {}", cr.criterion, cr.completeness));

            if let Some(ref impact) = cr.impact_description {
                w.bold_line("IMPACT:");
                w.paragraph(impact);
                w.spacing(1.0);
            }

            if !cr.what_documented.is_empty() {
                w.bold_line("WHAT'S DOCUMENTED:");
                for item in &cr.what_documented {
                    w.bullet(item);
                }
                w.spacing(1.0);
            }

            if !cr.gaps.is_empty() {
                w.bold_line("GAPS:");
                for gap in &cr.gaps {
                    w.bullet(gap);
                }
                w.spacing(1.0);
            }

            if !cr.recommendations.is_empty() {
                w.bold_line("RECOMMENDATIONS:");
                for rec in &cr.recommendations {
                    w.bullet(&format!("[{}] {}", rec.priority.to_uppercase(), rec.action));
                }
                w.spacing(1.0);
            }

            w.horizontal_rule();
            w.spacing(1.0);
        }
    }

    // NIST reference footer
    w.spacing(3.0);
    w.horizontal_rule();
    w.small_text("Risk levels follow NIST 800-30 classification:");
    w.small_text("  Low (0-25%) | Moderate (26-50%) | High (51-75%) | Very High (76-100%)");

    w.finish()
}

/// Count criteria by completeness level across all categories.
fn count_completeness(categories: &[ReportCategory]) -> (usize, usize, usize) {
    let mut complete = 0;
    let mut partial = 0;
    let mut missing = 0;
    for cat in categories {
        for cr in &cat.criteria {
            match cr.completeness.as_str() {
                "complete" => complete += 1,
                "partial" => partial += 1,
                "missing" => missing += 1,
                _ => {}
            }
        }
    }
    (complete, partial, missing)
}

/// Format a JSON value as a display string.
fn format_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}
