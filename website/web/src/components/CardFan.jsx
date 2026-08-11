// A modest run rather than a royal flush - this is a low-stakes kitchen game.
const CARDS = [
  { rank: "5", suit: "♣", tone: "dark" },
  { rank: "6", suit: "♦", tone: "red" },
  { rank: "7", suit: "♠", tone: "dark" },
  { rank: "8", suit: "♥", tone: "red" },
  { rank: "9", suit: "♣", tone: "dark" },
];

export default function CardFan() {
  return (
    <div className="card-fan" aria-hidden="true">
      {CARDS.map((c, i) => (
        <span key={i} className={`play-card ${c.tone}`}>
          <span className="play-card-rank">{c.rank}</span>
          <span className="play-card-suit">{c.suit}</span>
        </span>
      ))}
    </div>
  );
}
