use crate::risk_assessment::model::{CategoryResult, CategoryScore, OverallScore, ScoringResult};
use std::collections::HashMap;

/// NIST 800-30 category weights as defined in the feature specification.
/// Weights sum to 1.0 (100%).
const CATEGORY_WEIGHTS: &[(&str, f64)] = &[
    ("pt", 0.30),
    ("vex", 0.20),
    ("sar", 0.20),
    ("dast", 0.15),
    ("sast", 0.10),
    ("threat_model", 0.05),
];

/// All known categories for detecting missing ones.
const ALL_CATEGORIES: &[&str] = &["pt", "vex", "sar", "dast", "sast", "threat_model"];

/// NIST 800-30 risk level thresholds.
/// These are specific to NIST 800-30 methodology, not CVSS.
///   0–25%: Low
///  26–50%: Moderate
///  51–75%: High
///  76–100%: Very High
fn classify_risk_level(score: f64) -> &'static str {
    let pct = score * 100.0;
    if pct <= 25.0 {
        "Low"
    } else if pct <= 50.0 {
        "Moderate"
    } else if pct <= 75.0 {
        "High"
    } else {
        "Very High"
    }
}

/// Compute the average score for a single category from its criteria scores.
fn compute_category_score(criteria_scores: &[f64]) -> f64 {
    if criteria_scores.is_empty() {
        return 0.0;
    }
    let sum: f64 = criteria_scores.iter().sum();
    sum / criteria_scores.len() as f64
}

/// Compute the completeness-based overall score from all criteria across categories.
///
/// The score is a fraction (0.0–1.0):
///   (complete_count * 1.0 + partial_count * 0.5) / total_criteria
///
/// This replaces the previous weighted-average approach. Per-category
/// `CategoryScore` values (weight, weighted_score) remain unchanged so
/// downstream consumers still have per-category detail.
fn compute_completeness_score(categories: &[CategoryResult]) -> f64 {
    let mut complete = 0usize;
    let mut partial = 0usize;
    let mut total = 0usize;

    for cat in categories {
        if !cat.processed || cat.criteria.is_empty() {
            continue;
        }
        for criterion in &cat.criteria {
            total += 1;
            match criterion.completeness.as_str() {
                "complete" => complete += 1,
                "partial" => partial += 1,
                _ => {} // "missing" contributes 0
            }
        }
    }

    if total == 0 {
        return 0.0;
    }

    (complete as f64 * 1.0 + partial as f64 * 0.5) / total as f64
}

/// Compute the full scoring result from category results.
/// This is the main entry point for the scoring engine.
pub fn compute_scoring_result(categories: &[CategoryResult]) -> ScoringResult {
    let weights: HashMap<&str, f64> = CATEGORY_WEIGHTS.iter().copied().collect();

    // Compute per-category scores from processed categories with criteria
    let mut present_categories: Vec<String> = Vec::new();
    let mut scored_categories: Vec<CategoryScore> = Vec::new();

    for cat in categories {
        if !cat.processed || cat.criteria.is_empty() {
            continue;
        }

        let criteria_scores: Vec<f64> = cat.criteria.iter().map(|c| c.score).collect();
        let avg_score = compute_category_score(&criteria_scores);
        let weight = weights.get(cat.category.as_str()).copied().unwrap_or(0.0);
        let weighted = avg_score * weight;

        present_categories.push(cat.category.clone());

        scored_categories.push(CategoryScore {
            category: cat.category.clone(),
            score: avg_score,
            weight,
            weighted_score: weighted,
            risk_level: classify_risk_level(avg_score).to_string(),
            criteria_count: cat.criteria.len(),
        });
    }

    // Identify missing categories
    let missing: Vec<String> = ALL_CATEGORIES
        .iter()
        .filter(|c| !present_categories.iter().any(|p| p == **c))
        .map(|c| c.to_string())
        .collect();

    // Compute overall completeness-based score (0.0–1.0 fraction)
    let overall = compute_completeness_score(categories);

    ScoringResult {
        overall: OverallScore {
            score: overall,
            risk_level: classify_risk_level(overall).to_string(),
            missing_categories: missing,
        },
        categories: scored_categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk_assessment::model::{CategoryResult, CriterionResult};

    fn make_criterion_with_completeness(
        name: &str,
        score: f64,
        completeness: &str,
    ) -> CriterionResult {
        CriterionResult {
            id: "test-id".to_string(),
            criterion: name.to_string(),
            completeness: completeness.to_string(),
            risk_level: classify_risk_level(score).to_string(),
            score,
            details: None,
        }
    }

    fn make_criterion(name: &str, score: f64) -> CriterionResult {
        make_criterion_with_completeness(name, score, "complete")
    }

    fn make_category(name: &str, scores: &[f64]) -> CategoryResult {
        CategoryResult {
            category: name.to_string(),
            document_id: "doc-id".to_string(),
            processed: true,
            criteria: scores
                .iter()
                .enumerate()
                .map(|(i, &s)| make_criterion(&format!("criterion_{i}"), s))
                .collect(),
        }
    }

    fn make_category_with_completeness(
        name: &str,
        criteria: Vec<(&str, f64, &str)>,
    ) -> CategoryResult {
        CategoryResult {
            category: name.to_string(),
            document_id: "doc-id".to_string(),
            processed: true,
            criteria: criteria
                .into_iter()
                .enumerate()
                .map(|(i, (completeness, score, _risk))| {
                    make_criterion_with_completeness(&format!("criterion_{i}"), score, completeness)
                })
                .collect(),
        }
    }

    #[test]
    fn test_completeness_score_all_complete() {
        // All criteria are "complete" (default from make_category)
        // 9 criteria total, all complete
        // Score = (9 * 1.0) / 9 = 1.0
        let categories = vec![
            make_category("pt", &[0.8, 0.6]),       // 2 complete
            make_category("vex", &[0.5]),           // 1 complete
            make_category("sar", &[0.9, 0.7, 0.8]), // 3 complete
            make_category("dast", &[0.4]),          // 1 complete
            make_category("sast", &[0.6]),          // 1 complete
            make_category("threat_model", &[0.3]),  // 1 complete
        ];

        let result = compute_scoring_result(&categories);

        // All 9 criteria are "complete": (9*1.0)/9 = 1.0
        let expected = 1.0;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "Very High");
        assert!(result.overall.missing_categories.is_empty());
        assert_eq!(result.categories.len(), 6);
    }

    #[test]
    fn test_completeness_score_mixed() {
        // 2 complete, 1 partial, 1 missing = (2*1.0 + 1*0.5) / 4 = 2.5/4 = 0.625
        let categories = vec![make_category_with_completeness(
            "sar",
            vec![
                ("complete", 0.0, "Low"),
                ("complete", 0.0, "Low"),
                ("partial", 0.5, "Moderate"),
                ("missing", 0.8, "High"),
            ],
        )];

        let result = compute_scoring_result(&categories);

        let expected = 0.625;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "High");
    }

    #[test]
    fn test_completeness_score_missing_categories() {
        // Only PT and SAR available, both all complete
        // 2 criteria total, both complete: (2*1.0)/2 = 1.0
        let categories = vec![make_category("pt", &[0.8]), make_category("sar", &[0.6])];

        let result = compute_scoring_result(&categories);

        let expected = 1.0;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "Very High");
        assert_eq!(result.overall.missing_categories.len(), 4);
        assert!(
            result
                .overall
                .missing_categories
                .contains(&"vex".to_string())
        );
        assert!(
            result
                .overall
                .missing_categories
                .contains(&"dast".to_string())
        );
        assert!(
            result
                .overall
                .missing_categories
                .contains(&"sast".to_string())
        );
        assert!(
            result
                .overall
                .missing_categories
                .contains(&"threat_model".to_string())
        );
    }

    #[test]
    fn test_risk_level_boundaries() {
        // Low: 0-25%
        assert_eq!(classify_risk_level(0.0), "Low");
        assert_eq!(classify_risk_level(0.25), "Low");

        // Moderate: 26-50%
        assert_eq!(classify_risk_level(0.26), "Moderate");
        assert_eq!(classify_risk_level(0.50), "Moderate");

        // High: 51-75%
        assert_eq!(classify_risk_level(0.51), "High");
        assert_eq!(classify_risk_level(0.75), "High");

        // Very High: 76-100%
        assert_eq!(classify_risk_level(0.76), "Very High");
        assert_eq!(classify_risk_level(1.0), "Very High");
    }

    #[test]
    fn test_empty_categories() {
        let categories: Vec<CategoryResult> = vec![];
        let result = compute_scoring_result(&categories);

        assert!((result.overall.score).abs() < f64::EPSILON);
        assert_eq!(result.overall.risk_level, "Low");
        assert_eq!(result.overall.missing_categories.len(), 6);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_unprocessed_categories_excluded() {
        let mut categories = vec![make_category("pt", &[0.8])];
        categories.push(CategoryResult {
            category: "sar".to_string(),
            document_id: "doc-id".to_string(),
            processed: false,
            criteria: vec![make_criterion("c1", 0.5)],
        });

        let result = compute_scoring_result(&categories);

        // Only PT should be scored; SAR is unprocessed
        assert_eq!(result.categories.len(), 1);
        assert_eq!(result.categories[0].category, "pt");
        assert!(
            result
                .overall
                .missing_categories
                .contains(&"sar".to_string())
        );
        // 1 complete criterion: (1*1.0)/1 = 1.0
        assert!(
            (result.overall.score - 1.0).abs() < 1e-10,
            "Expected overall score 1.0, got {}",
            result.overall.score
        );
    }

    #[test]
    fn test_completeness_score_all_missing() {
        // All criteria are "missing"
        let categories = vec![make_category_with_completeness(
            "sar",
            vec![("missing", 0.9, "Very High"), ("missing", 0.7, "High")],
        )];

        let result = compute_scoring_result(&categories);

        // (0*1.0 + 0*0.5) / 2 = 0.0
        assert!((result.overall.score).abs() < f64::EPSILON);
        assert_eq!(result.overall.risk_level, "Low");
    }

    #[test]
    fn test_completeness_score_all_partial() {
        // All criteria are "partial"
        let categories = vec![make_category_with_completeness(
            "sar",
            vec![("partial", 0.5, "Moderate"), ("partial", 0.6, "High")],
        )];

        let result = compute_scoring_result(&categories);

        // (0*1.0 + 2*0.5) / 2 = 0.5
        let expected = 0.5;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "Moderate");
    }
}
