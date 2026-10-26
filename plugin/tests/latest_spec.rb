# The 'Latest message' display. Run: trmnlp test (from plugin/)
LATEST_NOW = '2030-01-02T12:00:00Z'.freeze
LATEST_FIELDS = { provider: 'gmail', email: 'me@example.com', display: 'latest' }.freeze
LATEST_BODY = "Hi all,\n\nThe Halloween party is on Friday at 8. Bring something to eat; we have drinks and music.\n\n" \
       "Costumes are welcome but not required. Parking is behind the house.\n\nSee you there!\nJürgen".freeze
LATEST_MESSAGE = { sender: 'Jürgen', sender_email: 'j@example.com', subject: 'Halloween party on Friday 🎃',
            timestamp: '2030-01-02T09:15:00+00:00', read: false, flagged: true, body: LATEST_BODY,
            truncated: false, has_attachments: true, encrypted: false,
            paragraphs: LATEST_BODY.split("\n\n"),
            markdown: "Hi all,\n\nThe party is on **Friday at 8**. Bring:\n\n- something to eat\n- a costume\n\nSee you there!  \nJürgen" }.freeze

def latest_data(message = LATEST_MESSAGE)
  { data: { success: true, display: 'latest', email: 'me@example.com', folder: 'INBOX', message: } }
end

def render_latest(view, data)
  trmnl.render(view:, now: LATEST_NOW, data:, transform: false, custom_fields: LATEST_FIELDS)
end

RSpec.describe 'Latest message display' do
  %w[full half_horizontal half_vertical quadrant].each do |view|
    it "shows the message in #{view}" do
      screen = render_latest(view, latest_data)
      expect(screen).to have_text('Halloween party on Friday')
      expect(screen).to have_no_problems
      expect(screen).to have_no_overflow
      expect(screen).to match_snapshot
    end

    it "cuts a very long body neatly in #{view}" do
      text = (['A long paragraph that keeps going and going, the way a newsletter does when it has a lot to say.'] * 40)
      long = LATEST_MESSAGE.merge(body: text.join("\n\n"), paragraphs: text, markdown: text.join("\n\n"), truncated: true)
      screen = render_latest(view, latest_data(long))
      expect(screen).to have_no_overflow
      expect(screen).to match_snapshot
    end
  end

  # Owner 2026-10-25: icons instead of the Flagged / Unread / Attachment labels
  it 'shows unread, flagged and attachments as icons' do
    screen = render_latest('full', latest_data)
    expect(screen).to have_css('svg circle', count: 1)            # unread dot
    expect(screen).to have_css("svg path[d^='M11.2691']", count: 1) # star
    expect(screen).to have_css("svg path[d^='M21.44']", count: 1)   # paperclip
    expect(screen).to have_no_text('Flagged')
    expect(screen).to have_no_css('.label--gray, .label--warning')
    expect(screen).to have_css('.label--filled', text: 'J')
  end

  it 'shows no state icons for a read, plain message' do
    plain = LATEST_MESSAGE.merge(read: true, flagged: false, has_attachments: false)
    screen = render_latest('full', latest_data(plain))
    expect(screen).to have_no_css('svg circle')
    expect(screen).to have_no_css("svg path[d^='M11.2691'], svg path[d^='M21.44']")
  end

  it 'says so for an encrypted message' do
    screen = render_latest('full', latest_data(LATEST_MESSAGE.merge(body: '', encrypted: true)))
    expect(screen).to have_text('encrypted')
  end

  it 'says so for an empty mailbox' do
    screen = render_latest('full', { data: { success: true, display: 'latest', email: 'me@example.com', message: nil } })
    expect(screen).to have_text('No mail')
  end

  it 'shows an error as an error label' do
    error = { data: { success: false, code: 'AUTH_FAILED', error: 'Auth Failed', message: 'Login failed.' } }
    screen = render_latest('full', error)
    expect(screen).to have_css('.label--error', text: 'Auth Failed')
    expect(screen).to have_text('Login failed.')
    expect(screen).to have_no_problems
  end
end

RSpec.describe 'Latest message markdown' do
  it 'shows bold and lists from the mail' do
    screen = render_latest('full', latest_data)
    expect(screen).to have_css('.content strong', text: 'Friday at 8')
    expect(screen).to have_css('.content li', count: 2)
  end

  it 'never turns HTML in a mail into real HTML' do
    evil = LATEST_MESSAGE.merge(markdown: 'Hello <img src=x onerror=alert(1)> <b>bold</b>')
    screen = render_latest('full', latest_data(evil))
    expect(screen).to have_no_css('.content img')
    expect(screen).to have_no_css('.content b')
    expect(screen).to have_text('<img src=x onerror=alert(1)>')
  end

  # 2026-10-26: on the X (variable font) a plain <strong> inherited the regular "wght" and showed no bold
  %w[og_plus v2].each do |device|
    it "shows bold text as bold on #{device}" do
      screen = trmnl.render(view: 'full', device:, now: LATEST_NOW, data: latest_data, transform: false, custom_fields: LATEST_FIELDS)
      weights = screen.evaluate("[...document.querySelectorAll('.content strong')].map(e => getComputedStyle(e).fontVariationSettings)")
      expect(weights).not_to be_empty
      expect(weights).to all(include('700'))
    end
  end

  # Owner 2026-10-26: the message header shows the personal level and the conversation count too
  it 'shows the personal level and the conversation badge in the message header' do
    screen = render_latest('full', latest_data(LATEST_MESSAGE.merge(personal: 'only', count: 3)))
    expect(screen).to have_css("svg path[d^='M5 6l6 6']", count: 1)
    expect(screen).to have_css('.label--outline', text: '3', count: 1)
    plain = render_latest('full', latest_data(LATEST_MESSAGE.merge(personal: nil, count: 1)))
    expect(plain).to have_no_css("svg path[d^='M5 6l6 6'], svg path[d^='M9 6l6 6']")
    expect(plain).to have_no_css('.label--outline')
  end
end
