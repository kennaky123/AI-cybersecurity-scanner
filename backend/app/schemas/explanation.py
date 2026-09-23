from pydantic import BaseModel


class FeatureContributionResponse(BaseModel):
    name: str
    value: float
    contribution: float


class ModelExplanationResponse(BaseModel):
    method: str
    output_space: str
    increasing_risk: list[FeatureContributionResponse]
    decreasing_risk: list[FeatureContributionResponse]
    limitation: str | None
