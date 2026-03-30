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

/// Compute the weighted overall score from per-category scores.
/// Only categories with actual data are included. Weights are re-normalized
/// to account for missing categories.
fn compute_weighted_score(category_scores: &HashMap<String, f64>) -> f64 {
    let weights: HashMap<&str, f64> = CATEGORY_WEIGHTS.iter().copied().collect();

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for (category, &score) in category_scores {
        let weight = weights.get(category.as_str()).copied().unwrap_or(0.0);
        if weight > 0.0 {
            weighted_sum += score * weight;
            total_weight += weight;
        }
    }

    if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    }
}

/// Compute the full scoring result from category results.
/// This is the main entry point for the scoring engine.
pub fn compute_scoring_result(categories: &[CategoryResult]) -> ScoringResult {
    let weights: HashMap<&str, f64> = CATEGORY_WEIGHTS.iter().copied().collect();

    // Compute per-category scores from processed categories with criteria
    let mut category_scores_map: HashMap<String, f64> = HashMap::new();
    let mut scored_categories: Vec<CategoryScore> = Vec::new();

    for cat in categories {
        if !cat.processed || cat.criteria.is_empty() {
            continue;
        }

        let criteria_scores: Vec<f64> = cat.criteria.iter().map(|c| c.score).collect();
        let avg_score = compute_category_score(&criteria_scores);
        let weight = weights.get(cat.category.as_str()).copied().unwrap_or(0.0);
        let weighted = avg_score * weight;

        category_scores_map.insert(cat.category.clone(), avg_score);

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
    let present: std::collections::HashSet<&str> =
        category_scores_map.keys().map(|s| s.as_str()).collect();
    let missing: Vec<String> = ALL_CATEGORIES
        .iter()
        .filter(|c| !present.contains(**c))
        .map(|c| c.to_string())
        .collect();

    // Compute overall weighted score (re-normalized for available categories)
    let overall = compute_weighted_score(&category_scores_map);

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

    fn make_criterion(name: &str, score: f64) -> CriterionResult {
        CriterionResult {
            id: "test-id".to_string(),
            criterion: name.to_string(),
            completeness: "complete".to_string(),
            risk_level: classify_risk_level(score).to_string(),
            score,
            details: None,
        }
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

    #[test]
    fn test_weighted_score_all_categories() {
        let categories = vec![
            make_category("pt", &[0.8, 0.6]),       // avg = 0.7, weight = 0.30
            make_category("vex", &[0.5]),           // avg = 0.5, weight = 0.20
            make_category("sar", &[0.9, 0.7, 0.8]), // avg = 0.8, weight = 0.20
            make_category("dast", &[0.4]),          // avg = 0.4, weight = 0.15
            make_category("sast", &[0.6]),          // avg = 0.6, weight = 0.10
            make_category("threat_model", &[0.3]),  // avg = 0.3, weight = 0.05
        ];

        let result = compute_scoring_result(&categories);

        // All categories present, no re-normalization needed
        // Expected: 0.7*0.30 + 0.5*0.20 + 0.8*0.20 + 0.4*0.15 + 0.6*0.10 + 0.3*0.05
        //         = 0.21 + 0.10 + 0.16 + 0.06 + 0.06 + 0.015 = 0.605
        let expected = 0.605;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "High");
        assert!(result.overall.missing_categories.is_empty());
        assert_eq!(result.categories.len(), 6);
    }

    #[test]
    fn test_weighted_score_missing_categories() {
        // Only PT and SAR available
        let categories = vec![
            make_category("pt", &[0.8]),  // avg = 0.8, weight = 0.30
            make_category("sar", &[0.6]), // avg = 0.6, weight = 0.20
        ];

        let result = compute_scoring_result(&categories);

        // Re-normalized: total available weight = 0.30 + 0.20 = 0.50
        // Weighted sum = 0.8*0.30 + 0.6*0.20 = 0.24 + 0.12 = 0.36
        // Re-normalized overall = 0.36 / 0.50 = 0.72
        let expected = 0.72;
        assert!(
            (result.overall.score - expected).abs() < 1e-10,
            "Expected overall score {expected}, got {}",
            result.overall.score
        );
        assert_eq!(result.overall.risk_level, "High");
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
        // Low: 0–25%
        assert_eq!(classify_risk_level(0.0), "Low");
        assert_eq!(classify_risk_level(0.25), "Low");

        // Moderate: 26–50%
        assert_eq!(classify_risk_level(0.26), "Moderate");
        assert_eq!(classify_risk_level(0.50), "Moderate");

        // High: 51–75%
        assert_eq!(classify_risk_level(0.51), "High");
        assert_eq!(classify_risk_level(0.75), "High");

        // Very High: 76–100%
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
    }
}
