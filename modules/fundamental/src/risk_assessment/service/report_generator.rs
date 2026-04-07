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
        let (page, layer) =
            self.doc
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
        self.layer()
            .use_text(text, size, Mm(x), Mm(self.y), font);
    }

    fn title(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_TITLE + 4.0);
        self.write_text(text, FONT_SIZE_TITLE, MARGIN_LEFT, &self.font_bold.clone());
        self.advance(LINE_HEIGHT_TITLE + 4.0);
    }

    fn heading(&mut self, text: &str) {
        self.ensure_space(LINE_HEIGHT_HEADING + 3.0);
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
            (
                Point::new(Mm(PAGE_WIDTH - MARGIN_RIGHT), Mm(self.y)),
                false,
            ),
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

/// Generate a PDF report from assessment data.
pub fn generate_report(data: &ReportData) -> Result<Vec<u8>, anyhow::Error> {
    let mut w = ReportWriter::new(&format!(
        "Risk Assessment Report - {}",
        data.assessment_id
    ))?;

    // ── Page 1: Executive Summary ───────────────────────────────────────

    w.title("Risk Assessment Report");
    w.spacing(2.0);

    w.key_value("Assessment ID:  ", &data.assessment_id);
    w.key_value("Group ID:  ", &data.group_id);
    w.key_value("Status:  ", &data.status);
    w.key_value("Date:  ", &data.created_at);

    w.spacing(3.0);
    w.horizontal_rule();

    // Overall risk score
    w.heading("Executive Summary");

    if let Some(ref scoring) = data.scoring {
        let score_pct = scoring.overall.score * 100.0;
        w.key_value(
            "Overall Risk Score:  ",
            &format!("{:.1}%", score_pct),
        );
        w.key_value("Risk Level:  ", &scoring.overall.risk_level);

        if !scoring.overall.missing_categories.is_empty() {
            w.spacing(2.0);
            w.bold_line("Missing Categories:");
            for cat in &scoring.overall.missing_categories {
                w.bullet(cat);
            }
        }

        // Summary of findings
        w.spacing(3.0);
        w.subheading("Summary of Findings");

        let (complete, partial, missing) = count_completeness(&data.categories);
        w.key_value("Complete criteria:  ", &complete.to_string());
        w.key_value("Partial criteria:  ", &partial.to_string());
        w.key_value("Missing criteria:  ", &missing.to_string());

        // Category scores table
        if !scoring.categories.is_empty() {
            w.spacing(3.0);
            w.subheading("Category Scores");

            let col_widths = [40.0, 25.0, 20.0, 30.0, 25.0, 30.0];
            w.table_row(
                &["Category", "Score", "Weight", "Weighted", "Risk", "Criteria"],
                &col_widths,
                true,
            );
            w.horizontal_rule();

            for cat in &scoring.categories {
                w.table_row(
                    &[
                        &cat.category,
                        &format!("{:.1}%", cat.score * 100.0),
                        &format!("{:.0}%", cat.weight * 100.0),
                        &format!("{:.1}%", cat.weighted_score * 100.0),
                        &cat.risk_level,
                        &cat.criteria_count.to_string(),
                    ],
                    &col_widths,
                    false,
                );
            }
        }

        // Risk prioritization: top risks
        w.spacing(3.0);
        w.subheading("Risk Prioritization");

        let mut top_risks: Vec<(&str, f64, &str)> = Vec::new();
        for cat in &data.categories {
            for cr in &cat.criteria {
                if cr.completeness != "complete" && cr.score > 0.0 {
                    top_risks.push((&cr.criterion, cr.score, &cr.risk_level));
                }
            }
        }
        top_risks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        if top_risks.is_empty() {
            w.body("No elevated risks identified.");
        } else {
            let col_widths = [80.0, 25.0, 30.0];
            w.table_row(&["Criterion", "Score", "Risk Level"], &col_widths, true);
            w.horizontal_rule();
            for (name, score, level) in top_risks.iter().take(10) {
                w.table_row(
                    &[name, &format!("{:.1}%", score * 100.0), level],
                    &col_widths,
                    false,
                );
            }
        }
    } else {
        w.body("No scoring data available.");
    }

    // ── Page 2+: Criteria Assessment Details ────────────────────────────

    w.new_page();
    w.title("Criteria Assessment Details");
    w.spacing(2.0);

    for cat in &data.categories {
        w.heading(&format!("Category: {}", cat.category));

        // Criteria overview table
        let col_widths = [8.0, 62.0, 30.0, 30.0, 25.0];
        w.table_row(
            &["#", "Criterion", "Completeness", "Risk Level", "Score"],
            &col_widths,
            true,
        );
        w.horizontal_rule();

        for (i, cr) in cat.criteria.iter().enumerate() {
            w.table_row(
                &[
                    &(i + 1).to_string(),
                    &cr.criterion,
                    &cr.completeness,
                    &cr.risk_level,
                    &format!("{:.1}%", cr.score * 100.0),
                ],
                &col_widths,
                false,
            );
        }

        w.spacing(3.0);

        // Detailed breakdown for partial/missing criteria
        for cr in &cat.criteria {
            if cr.completeness == "complete" {
                continue;
            }

            w.subheading(&cr.criterion);
            w.key_value("Completeness:  ", &cr.completeness);
            w.key_value("Risk Level:  ", &cr.risk_level);
            w.key_value("Score:  ", &format!("{:.1}%", cr.score * 100.0));

            if !cr.what_documented.is_empty() {
                w.spacing(1.0);
                w.bold_line("What is documented:");
                for item in &cr.what_documented {
                    w.bullet(item);
                }
            }

            if !cr.gaps.is_empty() {
                w.spacing(1.0);
                w.bold_line("Gaps identified:");
                for gap in &cr.gaps {
                    w.bullet(gap);
                }
            }

            if let Some(ref impact) = cr.impact_description {
                w.spacing(1.0);
                w.bold_line("Impact:");
                w.paragraph(impact);
            }

            if !cr.recommendations.is_empty() {
                w.spacing(1.0);
                w.bold_line("Recommendations:");
                for rec in &cr.recommendations {
                    w.bullet(&format!("[{}] {}", rec.priority, rec.action));
                }
            }

            w.spacing(2.0);
            w.horizontal_rule();
        }
    }

    // ── Final Page: Risk Assessment Matrix ──────────────────────────────

    w.new_page();
    w.title("Risk Assessment Matrix");
    w.spacing(2.0);

    w.small_text("Based on NIST 800-30 risk assessment methodology.");
    w.spacing(3.0);

    for cat in &data.categories {
        for cr in &cat.criteria {
            if cr.completeness == "complete" {
                continue;
            }

            // Extract risk details from the details JSON if available
            if let Some(ref details) = cr.details {
                w.subheading(&cr.criterion);

                // Threat scenarios
                if let Some(scenarios) = details.get("threat_scenarios") {
                    if let Some(arr) = scenarios.as_array() {
                        w.bold_line("Threat Scenarios:");
                        for scenario in arr {
                            if let Some(s) = scenario.as_str() {
                                w.bullet(s);
                            }
                        }
                    }
                }

                // Likelihood and impact
                if let Some(likelihood) = details.get("likelihood") {
                    w.key_value("Likelihood:  ", &format_json_value(likelihood));
                }
                if let Some(impact) = details.get("impact") {
                    w.key_value("Impact:  ", &format_json_value(impact));
                }
                if let Some(risk_level) = details.get("risk_level") {
                    w.key_value("Risk Level:  ", &format_json_value(risk_level));
                }

                w.spacing(2.0);
            }
        }
    }

    // NIST reference
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
