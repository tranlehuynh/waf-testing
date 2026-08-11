import { useRoute } from "./router.jsx";
import Nav from "./components/Nav.jsx";
import Footer from "./components/Footer.jsx";
import Home from "./pages/Home.jsx";
import Rules from "./pages/Rules.jsx";
import NotFound from "./pages/NotFound.jsx";

// Keep this list in step with the exact-match locations in nginx/default.conf,
// which decide whether a path gets a 200 or a real 404.
const ROUTES = {
  "/": Home,
  "/rules": Rules,
};

export default function App() {
  const path = useRoute();
  const Page = ROUTES[path] ?? NotFound;
  return (
    <>
      <Nav path={path} />
      <main>
        <Page />
      </main>
      <Footer />
    </>
  );
}
