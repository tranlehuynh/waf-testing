import { Link } from "../router.jsx";
import CardFan from "../components/CardFan.jsx";

const NIGHT = [
  {
    when: "Seven o'clock",
    text: "Doors open, records go on. Come early if you want the good chair.",
  },
  {
    when: "Low stakes, no ego",
    text: "Twenty in, chips at the door. We're here for the company - the pot is just the excuse.",
  },
  {
    when: "Till the snacks run out",
    text: "No blind clock, no bust-out drama. We play until someone raids the kitchen and finds it empty.",
  },
];

const DETAILS = [
  "Records on the turntable",
  "Chips counted by half past",
  "Phones face-down",
  "Somebody's dog under the table",
];

export default function Home() {
  return (
    <>
      <section className="hero">
        <CardFan />
        <p className="eyebrow">Every Friday · since 2019</p>
        <h1>Friday Night Poker</h1>
        <p className="tagline">
          A low-stakes home game in the back room. Doors open at seven, chips are
          counted by half past, and nobody is getting rich.
        </p>
        <Link to="/rules" className="btn">
          Read the house rules
        </Link>
      </section>

      <section className="section">
        <h2>How the night goes</h2>
        <div className="panel-grid">
          {NIGHT.map((n) => (
            <article className="panel" key={n.when}>
              <h3>{n.when}</h3>
              <p>{n.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section house">
        <h2>The house</h2>
        <p className="prose">
          It is a kitchen table, a lamp turned low, and five people who have been
          doing this long enough to know each other's tells. Bring something to
          share if you like — a bottle, a record, or a story about the hand you
          should have folded.
        </p>
        <ul className="chips">
          {DETAILS.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
        <blockquote className="quote">
          <p>Best hand I ever folded was at this table.</p>
          <cite>Mai — four years a regular</cite>
        </blockquote>
      </section>
    </>
  );
}
