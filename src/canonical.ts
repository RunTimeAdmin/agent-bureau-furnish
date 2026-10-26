// RFC 8785 (JCS) canonical JSON for the values events contain: objects with
// keys sorted by UTF-16 code unit, arrays, strings, finite numbers, booleans
// and null. JCS adopts JavaScript's own string and number serialization, so
// JSON.stringify handles the leaves.
export function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const members = Object.keys(record)
      .filter(key => record[key] !== undefined)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalize(record[key])}`);
    return `{${members.join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error("Cannot canonicalize a non-finite number");
  }
  const leaf = JSON.stringify(value);
  if (leaf === undefined) throw new Error(`Cannot canonicalize ${typeof value}`);
  return leaf;
}
