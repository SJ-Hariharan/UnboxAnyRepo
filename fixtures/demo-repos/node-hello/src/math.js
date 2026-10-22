export function add(a, b) {
  return a + b;
}

export function mean(values) {
  if (values.length === 0) throw new RangeError('mean of empty list');
  return values.reduce(add, 0) / values.length;
}
