function transform(input) {
  const { trmnl, ...rest } = input;
  
  return { "data": rest };
}