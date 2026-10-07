export default function PagePlaceholder({ eyebrow, title, description }) {
  return (
    <section>
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p className="lead">{description}</p>
      <div className="placeholder-card">
        <span>Sẽ có trong giai đoạn sau</span>
        <p>Chưa có AI prediction hoặc model giả trong Phase 1.</p>
      </div>
    </section>
  )
}
