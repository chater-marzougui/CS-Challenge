import Terminal from "./Terminal";
import "../../styles.css";

export default function TerminalsBox() {
  return (
    <div className="terminal-box">
      <Terminal bgColor={"#661b1c"} promptColor="red" welcomMsg="Attacker" />
      <Terminal bgColor={"#235347"} promptColor="white" welcomMsg="Defender" />
    </div>
  );
}
