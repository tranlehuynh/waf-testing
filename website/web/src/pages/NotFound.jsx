import { Link } from "../router.jsx";

export default function NotFound() {
  return (
    <section className="hero notfound">
      <p className="eyebrow">404</p>
      <h1>No seat here</h1>
      <p className="tagline">
        You have wandered off into the pantry. Nothing is dealt in this room —
        the game is back the other way.
      </p>
      <div className="notfound-actions">
        <Link to="/" className="btn">
          Back to the night
        </Link>
        <Link to="/rules" className="link-quiet">
          or read the house rules
        </Link>
      </div>
    </section>
  );
}
