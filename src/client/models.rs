use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Job {
    pub hash: String,
    pub name: String,
    pub version: String,
    pub distributions: Vec<String>,
    pub attempt: u64,
    pub assignment_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OpenGrepRulesResponse {
    pub hash: String,
    pub rules: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OpenGrepFinding {
    pub rule_id: String,
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub message: String,
    pub severity: String,
    pub evidence: String,
    pub confidence: String,
    pub execution_context: String,
    pub inspector_url: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SubmitOpenGrepResultsSuccess {
    pub name: String,
    pub version: String,
    pub attempt: u64,
    pub assignment_id: String,
    pub commit: String,
    pub duration_ms: u64,
    pub findings: Vec<OpenGrepFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_reason: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SubmitOpenGrepResultsError {
    pub name: String,
    pub version: String,
    pub attempt: u64,
    pub assignment_id: String,
    pub duration_ms: u64,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum OpenGrepScanResult {
    Success(SubmitOpenGrepResultsSuccess),
    Error(SubmitOpenGrepResultsError),
}

#[cfg(test)]
mod tests {
    use super::Job;

    #[test]
    fn job_deserializes_assignment_lease() {
        let job: Job = serde_json::from_str(
            r#"{
                "hash": "rules-commit",
                "name": "example",
                "version": "1.2.3",
                "distributions": ["https://example.com/example.whl"],
                "attempt": 2,
                "assignment_id": "4e3702e8-27a3-46e6-b51c-4779a94fa4ab"
            }"#,
        )
        .unwrap();

        assert_eq!(job.attempt, 2);
        assert_eq!(job.assignment_id, "4e3702e8-27a3-46e6-b51c-4779a94fa4ab");
    }

    #[test]
    fn job_requires_assignment_lease() {
        let result = serde_json::from_str::<Job>(
            r#"{
                "hash": "rules-commit",
                "name": "example",
                "version": "1.2.3",
                "distributions": []
            }"#,
        );

        assert!(result.is_err());
    }
}
