import React from "react";

export default function App() {
  const [name, setName] = React.useState("nexus");
  return (
    <main>
      <h1>Hello {name}</h1>
      <button onClick={() => setName("auditor")}>Rename</button>
    </main>
  );
}
