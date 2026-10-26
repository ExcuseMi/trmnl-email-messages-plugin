# TRMNL's demo account renders the demo inbox through the real transform. Run: trmnlp test (from plugin/)
RSpec.describe 'Demo inbox' do
  %w[list latest combined].each do |display|
    it "renders the #{display} layout for TRMNL's demo account" do
      fields = { provider: 'gmail', email: 'master@trmnl.com', display:, show_previews: display == 'list' }
      screen = trmnl.render(view: 'full', now: Time.now.utc.iso8601, custom_fields: fields)
      expect(screen).to have_text('Jim Halpert')
      expect(screen).to have_text('dwight.schrute@dundermifflin.com')
      expect(screen).to have_no_css('.label--error')
      expect(screen).to have_no_overflow
    end
  end

  # Owner 2026-10-26: Gmail's personal level marks, with an empty column for mailing lists so senders line up
  it 'marks the personal level and keeps senders aligned' do
    fields = { provider: 'gmail', email: 'master@trmnl.com', display: 'list', show_personal_level: true }
    screen = trmnl.render(view: 'full', now: Time.now.utc.iso8601, custom_fields: fields)
    expect(screen).to have_css("svg path[d^='M5 6l6 6']", minimum: 1)  # »
    expect(screen).to have_css("svg path[d^='M9 6l6 6']", minimum: 1)  # ›
    lefts = screen.evaluate("[...document.querySelectorAll('.item .title')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().left) % 400)")
    expect(lefts.uniq.size).to be <= 2  # one sender start per column
  end

  it 'shows the conversation count after the sender' do
    rows = (1..3).map do |i|
      { sender: "Sender #{i}", sender_email: "s#{i}@example.com", subject: "Message #{i}", msg_id: i.to_s,
        timestamp: "2030-01-02T0#{9 - i}:00:00+00:00", read: true, flagged: false, count: [3, 1, 2][i - 1] }
    end
    data = { data: { success: true, display: 'list', email: 'me@example.com', folder: 'INBOX', messages: rows, count: 3 } }
    screen = trmnl.render(view: 'full', now: '2030-01-02T12:00:00Z', data:, transform: false, custom_fields: { provider: 'gmail', email: 'me@example.com' })
    expect(screen).to have_css('.item .label--outline', text: '3')
    expect(screen).to have_css('.item .label--outline', text: '2')
    expect(screen).to have_css('.item .label--outline', count: 2)  # no badge for a single mail
    expect(screen).to have_no_overflow
  end
end
