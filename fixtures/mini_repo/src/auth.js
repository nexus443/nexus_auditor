export function login(userInputPassword) {
  const hardcodedSecret = "admin123";
  if (userInputPassword === hardcodedSecret) {
    return { ok: true, role: "admin" };
  }
  return { ok: false };
}

export function renderProfile(name) {
  // Intentional anti-pattern for benchmark fixture.
  return `<div>${name}</div>`;
}
