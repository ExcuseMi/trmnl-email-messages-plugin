# List with the latest message: the list left, the newest message with its text right. Run: trmnlp test (from plugin/)
COMBINED_NOW = '2030-01-02T12:00:00Z'.freeze
COMBINED_FIELDS = { provider: 'gmail', email: 'me@example.com', display: 'combined' }.freeze
COMBINED_BODY = "Hi all,\n\nThe party is on Friday at 8. Bring something to eat; we have drinks and music.\n\nSee you there!".freeze
COMBINED_MAIN = { sender: 'Jürgen', sender_email: 'j@example.com', subject: 'Halloween party on Friday',
                  timestamp: '2030-01-02T11:00:00+00:00', read: false, flagged: true, truncated: false,
                  has_attachments: false, encrypted: false, body: COMBINED_BODY, paragraphs: COMBINED_BODY.split("\n\n"),
                  markdown: COMBINED_BODY }.freeze
# Newest first, as the plugin sorts them: four from today, then yesterday
COMBINED_LIST = (1..10).map do |i|
  { sender: "Sender #{i}", sender_email: "s#{i}@example.com", subject: "Earlier message number #{i}",
    timestamp: "2030-01-0#{i <= 4 ? 2 : 1}T#{format('%02d', 11 - i)}:00:00+00:00", read: i.even?, flagged: i == 3, msg_id: i.to_s }
end.freeze
COMBINED_DATA = { data: { success: true, display: 'combined', email: 'me@example.com', folder: 'INBOX',
                          message: COMBINED_MAIN, messages: [COMBINED_MAIN.slice(:sender, :sender_email, :subject, :timestamp, :read, :flagged).merge(msg_id: '11')] + COMBINED_LIST.first(9), count: 10 } }.freeze

RSpec.describe 'List with the latest message' do
  [%w[og_plus full], %w[og_plus half_horizontal], %w[og_plus half_vertical], %w[og_plus quadrant], %w[v2 full]].each do |device, view|
    it "shows the newest message and the list on #{device} #{view}" do
      screen = trmnl.render(view:, device:, now: COMBINED_NOW, data: COMBINED_DATA, transform: false, custom_fields: COMBINED_FIELDS)
      expect(screen).to have_text('Halloween party on Friday')
      expect(screen).to have_text('Earlier message number 1') unless view == 'quadrant'
      if %w[full half_horizontal].include?(view)
        # One line between list and message, with an opening at the open message's row (owner 2026-10-25)
        expect(screen).to have_css('.border--v-black', count: 1)
        expect(screen).to have_no_css("[class*='bg--gray']")  # owner 2026-10-26: no row backgrounds
        expect(screen).to have_css('.columns .item', text: 'Earlier message number 1')          # beside the line
        expect(screen).to have_no_css('.columns .item', text: 'Halloween party on Friday')       # in the opening
        expect(screen).to have_css('.border--v-black + .columns, .grow > .columns', minimum: 1)
      end
      expect(screen).to have_no_overflow
      expect(screen).to have_no_problems
      expect(screen).to match_snapshot
    end
  end

  it 'shows previews under the other rows when switched on' do
    rows = COMBINED_DATA[:data][:messages].each_with_index.map { |m, i| i.zero? ? m : m.merge(paragraphs: ["Preview text of row #{i}"]) }
    data = { data: COMBINED_DATA[:data].merge(messages: rows) }
    screen = trmnl.render(view: 'full', device: 'og_plus', now: COMBINED_NOW, data:, transform: false, custom_fields: COMBINED_FIELDS)
    expect(screen).to have_text('Preview text of row 1')
    expect(screen).to have_no_overflow
    expect(screen).to match_snapshot
  end
end
