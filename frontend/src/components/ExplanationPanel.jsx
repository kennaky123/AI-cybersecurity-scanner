function featureLabel(name) {
  return name.replaceAll('_', ' ').replace(/^./, (character) => character.toUpperCase())
}

function ContributionList({ title, features, direction }) {
  return (
    <div className={`contribution-group ${direction}`}>
      <h3>{title}</h3>
      {features.length ? (
        <div className="contribution-list">
          {features.map((feature) => (
            <div className="contribution-row" key={`${direction}-${feature.name}`}>
              <div>
                <strong>{featureLabel(feature.name)}</strong>
                <small>Giá trị quan sát: {Number(feature.value).toPrecision(4)}</small>
              </div>
              <code>{feature.contribution > 0 ? '+' : ''}{feature.contribution.toFixed(4)}</code>
            </div>
          ))}
        </div>
      ) : <p className="muted">Không có đặc trưng đáng kể theo hướng này.</p>}
    </div>
  )
}

export default function ExplanationPanel({ explanation, riskLabel }) {
  if (!explanation) return null
  const available = explanation.method !== 'UNAVAILABLE'
  return (
    <div className="result-section explanation-panel">
      <div className="explanation-heading">
        <div>
          <h2>Vì sao model đưa ra kết quả này?</h2>
          <p>Đóng góp của các đặc trưng trong lượt quét. Dự đoán vẫn đến từ model ML đã được huấn luyện.</p>
        </div>
        <span className={`method-badge ${available ? '' : 'unavailable'}`}>{explanation.method.replaceAll('_', ' ')}</span>
      </div>

      {available ? (
        <div className="contribution-grid">
          <ContributionList
            title={`Top features increasing ${riskLabel} risk`}
            features={explanation.increasing_risk}
            direction="increasing"
          />
          <ContributionList
            title={`Top features decreasing ${riskLabel} risk`}
            features={explanation.decreasing_risk}
            direction="decreasing"
          />
        </div>
      ) : <p className="muted">Model này chưa có giải thích cục bộ được hỗ trợ.</p>}

      <div className="explanation-note">
        <strong>{explanation.output_space.replaceAll('_', ' ')}</strong>
        <span>{explanation.limitation}</span>
      </div>
    </div>
  )
}
