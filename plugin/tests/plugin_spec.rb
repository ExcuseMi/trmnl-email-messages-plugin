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
