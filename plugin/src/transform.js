// Errors that pass on their own: keep the last mail on screen instead of an error.
// The backend reads mail at most once per 5 minutes (THROTTLED) and stores none of it.
const KEEP_PREVIOUS = ["THROTTLED", "TIMEOUT", "CONNECTION", "PROTOCOL", "UNEXPECTED_ERROR"];

function transform(input) {
  const { trmnl, ...rest } = input;
  const previous = (trmnl && trmnl.previous_merge_variables) || {};
  const hasPrevious = previous.data && Array.isArray(previous.data.messages);
  const failedFetch = Object.keys(rest).length === 0;

  if (hasPrevious && (failedFetch || KEEP_PREVIOUS.includes(rest.code))) {
    return previous;
  }
  return { "data": rest };
}
