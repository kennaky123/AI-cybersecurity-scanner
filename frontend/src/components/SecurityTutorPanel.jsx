function List({ title, items, tone = '' }) {
  return <div className={`tutor-list ${tone}`}><h3>{title}</h3><ul>{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</ul></div>
}

export default function SecurityTutorPanel({ education }) {
  if (!education) return null
  return (
    <section className="result-section tutor-panel">
      <div className="explanation-heading">
        <div><h2>Trợ giảng bảo mật: học từ kết quả quét</h2><p>Phần này chuyển bằng chứng tĩnh thành cách giải thích dễ hiểu. “Có thể” là khả năng, không phải bằng chứng hành vi thực tế.</p></div>
        <span className="method-badge">DỰA TRÊN BẰNG CHỨNG</span>
      </div>
      <p className="tutor-summary">{education.summary}</p>
      <div className="tutor-grid">
        <List title="Vì sao đáng chú ý?" items={education.evidence} />
        <List title="Có thể gây hại theo hướng nào?" items={education.possible_capabilities} tone="possible" />
        <List title="Người dùng nên làm gì?" items={education.recommended_actions} tone="actions" />
      </div>
      <div className="explanation-note"><strong>GIỚI HẠN</strong><span>{education.limitation}</span></div>
    </section>
  )
}
