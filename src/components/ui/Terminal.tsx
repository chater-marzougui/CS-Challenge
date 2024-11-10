import { ReactTerminal } from "react-terminal";
type TerminalProps = {
  bgColor: string;
  promptColor: string;
  welcomMsg: string;
};
export default function Terminal({
  bgColor,
  promptColor,
  welcomMsg,
}: TerminalProps) {
  const commands = {
    hello: "hello",
  };
  return (
    <ReactTerminal
      commands={commands}
      themes={{
        "my-custom-theme": {
          themeBGColor: bgColor,
          themeToolbarColor: "#DBDBDB",
          themeColor: "#FFFEFC",
          themePromptColor: promptColor,
        },
      }}
      theme="my-custom-theme"
      welcomeMessage={welcomMsg}
      showControlBar={false}
      showControlButtons={false}
      enableInput={false}
      prompt="hello"
    />
  );
}