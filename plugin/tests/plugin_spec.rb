# Run: trmnlp test (from plugin/)
MESSAGES = [
  { sender: 'Book Club', sender_email: 'club@example.com', read: false, flagged: false,
    subject: "Next month's book: a long story about a lighthouse keeper and the sea", timestamp: '2030-01-02T09:15:00+00:00' },
  { sender: 'Anna', sender_email: 'anna@example.com', read: true, flagged: false,
    subject: '[garden-group] Watering plan for the holidays (week 2)', timestamp: '2030-01-02T04:30:00+00:00' },
  { sender: 'Jürgen', sender_email: 'j@example.com', read: false, flagged: true,
    subject: 'Café tonight 🎃', timestamp: '2030-01-01T20:28:00+00:00' },
  { sender: 'Bike Shop', sender_email: 'shop@example.com', read: true, flagged: true,
    subject: 'Your bike is ready: pick it up from 10 to 18', timestamp: '2030-01-01T11:09:00+00:00' }
].freeze
DATA = { data: { success: true, email: 'me@example.com', folder: 'INBOX', count: 4, messages: MESSAGES } }.freeze
FIELDS = { provider: 'gmail', email: 'me@example.com', group_by_date: 'yes' }.freeze
NOW = '2030-01-02T12:00:00Z'.freeze

RSpec.describe 'Email Messages' do
  %w[full half_horizontal half_vertical quadrant].each do |view|
    it "shows the mail in #{view}" do
      screen = trmnl.render(view:, now: NOW, data: DATA, transform: false, custom_fields: FIELDS)
      expect(screen).to have_text('Café tonight')
      expect(screen).to have_no_problems
      expect(screen).to match_snapshot
    end
  end

  # Owner 2026-10-25: no gray on 1-bit and 2-bit screens (dither is hard to read)
  it 'marks unread mail with a black bar and flagged mail with a star, without gray' do
    screen = trmnl.render(view: 'full', now: NOW, data: DATA, transform: false, custom_fields: FIELDS)
    expect(screen).to have_css('.meta.bg--black', count: MESSAGES.count { !_1[:read] })
    expect(screen).to have_css('.meta.bg--white', count: MESSAGES.count { _1[:read] })
    expect(screen).to have_css('.item svg', count: MESSAGES.count { _1[:flagged] })
    expect(screen).to have_no_css('.label--gray, .label--warning')
  end

  it 'shows an error as an error label' do
    error = { data: { success: false, code: 'AUTH_FAILED', error: 'Auth Failed', message: 'Login failed.' } }
    screen = trmnl.render(view: 'full', now: NOW, data: error, transform: false, custom_fields: FIELDS)
    expect(screen).to have_css('.label--error', text: 'Auth Failed')
  end

  it 'shows how long each step took on a timeout' do
    error = { data: { success: false, code: 'TIMEOUT', error: 'Timeout', message: 'The mail server took too long to answer.',
                      timing: { steps_ms: { connect: 410, login: 1220, select: 95, search: 1810 }, total_ms: 3535 } } }
    screen = trmnl.render(view: 'full', now: NOW, data: error, transform: false, custom_fields: FIELDS)
    expect(screen).to have_text('search 1810 ms')
  end
end

RSpec.describe 'Email Messages error screen' do
  it 'renders the error without problems' do
    error = { data: { success: false, code: 'AUTH_FAILED', error: 'Auth Failed', message: 'Login failed.' } }
    screen = trmnl.render(view: 'full', now: NOW, data: error, transform: false, custom_fields: FIELDS)
    expect(screen).to have_no_problems
    expect(screen).to match_snapshot
  end
end

PREVIEW_BODY = "Hi all,\n\nThe Halloween party is on Friday at 8. Bring something to eat; we have drinks and music.\n\n" \
               "Costumes are welcome but not required. Parking is behind the house.\n\nSee you there!\nJürgen".freeze
PREVIEW_DATA = { data: { success: true, display: 'preview', email: 'me@example.com', folder: 'INBOX', count: 4,
                         messages: MESSAGES.map.with_index do |m, i|
                           m.merge(body: PREVIEW_BODY, paragraphs: PREVIEW_BODY.split("\n\n").rotate(i), encrypted: false)
                         end } }.freeze

RSpec.describe 'List with preview' do
  %w[full half_horizontal half_vertical quadrant].each do |view|
    it "shows every entry's text in #{view}" do
      screen = trmnl.render(view:, now: NOW, data: PREVIEW_DATA, transform: false, custom_fields: FIELDS.merge(display: 'preview'))
      expect(screen).to have_css('.item .description[data-clamp]', minimum: view == 'quadrant' ? 1 : 2)
      expect(screen).to have_text('Hi all,')
      expect(screen).to have_no_problems
      expect(screen).to match_snapshot
    end
  end

  # Owner 2026-10-25: yes/no selects became switches; installs from before keep their saved yes/no
  [[true, true], ['yes', true], [false, false], ['no', false]].each do |value, grouped|
    it "groups by date for the switch value #{value.inspect}" do
      screen = trmnl.render(view: 'full', now: NOW, data: DATA, transform: false, custom_fields: FIELDS.merge(group_by_date: value))
      grouped ? expect(screen).to(have_text('Yesterday')) : expect(screen).to(have_no_text('Yesterday'))
    end
  end
end
