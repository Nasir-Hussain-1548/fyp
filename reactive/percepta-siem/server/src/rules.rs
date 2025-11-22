'''use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub condition: Condition,
    pub action: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Condition {
    #[serde(default)]
    pub all: Vec<Clause>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Clause {
    pub field: String,
    pub equals: String,
}
''