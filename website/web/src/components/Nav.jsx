import { Link } from "../router.jsx";

export default function Nav({ path }) {
  return (
    <header className="nav">
      <Link to="/" className="brand">
        <span className="brand-suit" aria-hidden="true">♠</span>
        <span className="brand-name">Friday Night</span>
      </Link>
      <nav>
        <Link to="/" className={path === "/" ? "active" : ""}>
          The night
        </Link>
        <Link to="/rules" className={path === "/rules" ? "active" : ""}>
          House rules
        </Link>
        <Link to="/account" className={path === "/account" ? "active" : ""}>
          Account
        </Link>
      </nav>
    </header>
  );
}
