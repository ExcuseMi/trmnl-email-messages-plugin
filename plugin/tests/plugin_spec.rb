# Run: trmnlp test (from plugin/)
MESSAGES = [
  { sender: 'Humble Bundle', sender_email: 'news@humble.example', read: false, flagged: false,
    subject: "It's time to build Blender: learn open-sourced 3D game development!", timestamp: '2030-01-02T09:15:00+00:00' },
  { sender: 'apswood', sender_email: 'notifications@github.example', read: true, flagged: false,
    subject: '[trmnl-email-messages-plugin] Security contact (Issue #2)', timestamp: '2030-01-02T04:30:00+00:00' },
  { sender: 'Jürgen', sender_email: 'j@example.com', read: false, flagged: true,
    subject: 'Café tonight 🎃', timestamp: '2030-01-01T20:28:00+00:00' },
  { sender: 'Kickstarter', sender_email: 'k@example.com', read: true, flagged: true,
    subject: 'One backpack that expands from 20L to 40L', timestamp: '2030-01-01T11:09:00+00:00' }
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

  it 'marks read mail gray and flagged mail as a warning' do
    screen = trmnl.render(view: 'full', now: NOW, data: DATA, transform: false, custom_fields: FIELDS)
    expect(screen).to have_css('.label--warning', minimum: 2)
    expect(screen).to have_css('.label--gray', minimum: 2)
  end

  it 'shows an error as an error label' do
    error = { data: { success: false, code: 'AUTH_FAILED', error: 'Auth Failed', message: 'Login failed.' } }
    screen = trmnl.render(view: 'full', now: NOW, data: error, transform: false, custom_fields: FIELDS)
    expect(screen).to have_css('.label--error', text: 'Auth Failed')
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
                         messages: [MESSAGES[0].merge(expanded: true, body: PREVIEW_BODY, paragraphs: PREVIEW_BODY.split("\n\n"), has_attachments: false,
                                                      encrypted: false), *MESSAGES[1..]] } }.freeze

RSpec.describe 'List with preview' do
  %w[full half_horizontal half_vertical quadrant].each do |view|
    it "opens the newest entry in #{view}" do
      screen = trmnl.render(view:, now: NOW, data: PREVIEW_DATA, transform: false, custom_fields: FIELDS.merge(display: 'preview'))
      expect(screen).to have_css('.item--emphasis-2', count: 1)
      expect(screen).to have_text('The Halloween party is on Friday')
      expect(screen).to have_no_problems
      expect(screen).to match_snapshot
    end
  end
end
