# A short latest message leaves space: the messages before it follow as rows. Run: trmnlp test (from plugin/)
ROWS_NOW = '2030-01-02T12:00:00Z'.freeze
ROWS_FIELDS = { provider: 'gmail', email: 'me@example.com', display: 'latest' }.freeze
ROWS_MAIN = { sender: 'Anna', sender_email: 'anna@example.com', subject: 'Lunch on Friday?', timestamp: '2030-01-02T11:00:00+00:00',
              read: false, flagged: false, truncated: false, has_attachments: false, encrypted: false,
              body: 'Shall we meet at noon?', paragraphs: ['Shall we meet at noon?'], markdown: 'Shall we meet at noon?' }.freeze
ROWS_OTHERS = (1..8).map do |i|
  { sender: "Sender #{i}", sender_email: "s#{i}@example.com", subject: "Earlier message number #{i}",
    timestamp: "2030-01-0#{i <= 3 ? 2 : 1}T#{format('%02d', 10 - i)}:00:00+00:00", read: i.even?, flagged: i == 3 }
end.freeze

def render_rows(view, device, main, others = ROWS_OTHERS)
  data = { data: { success: true, display: 'latest', email: 'me@example.com', folder: 'INBOX', message: main, others: } }
  trmnl.render(view:, device:, now: ROWS_NOW, data:, transform: false, custom_fields: ROWS_FIELDS)
end

RSpec.describe 'Latest message with rows' do
  %w[og_plus v2].each do |device|
    %w[full half_vertical].each do |view|
      it "fills the space under a short message with earlier mail on #{device} #{view}" do
        screen = render_rows(view, device, ROWS_MAIN)
        expect(screen).to have_text('Shall we meet at noon?')
        expect(screen).to have_text('Earlier message number 1')
        expect(screen).to have_no_overflow
        expect(screen).to have_no_problems
        expect(screen).to match_snapshot
      end
    end
  end

  it 'shows no rows under a long message' do
    long = (['A long paragraph that keeps going, the way a newsletter does when it has a lot to say.'] * 20)
    main = ROWS_MAIN.merge(body: long.join("\n\n"), paragraphs: long, markdown: long.join("\n\n"))
    screen = render_rows('full', 'og_plus', main)
    expect(screen).to have_no_text('Earlier message number 1')
  end
end
