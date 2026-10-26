# Latest message text size follows its length, per screen. Run: trmnlp test (from plugin/)
SIZED_BODY = "Dear parents,\n\nBecause of the storm we ask you not to wait at the gate when you pick up the children at 3 pm.\n\nToddlers and pupils of years 3 to 6: please pick them up in the classroom.\n\nPupils of years 1 and 2 wait under the gallery near the after-school care.\n\nParents may walk straight to the classroom. This way the children can leave safely and quickly.\n\nThanks for your understanding!".freeze
SIZED_NOW = '2030-01-02T12:00:00Z'
SIZED_FIELDS = { provider: 'gmail', email: 'me@example.com', display: 'latest' }
SIZED_MSG = { sender: 'Teacher Name', sender_email: 'teacher@school.example', subject: 'Picking up the children today',
        timestamp: '2030-01-01T13:31:00+00:00', read: true, flagged: false, truncated: false, has_attachments: false, encrypted: false }
RSpec.describe 'Latest message text size' do
  %w[v2 og_plus].each do |device|
    %w[full half_horizontal half_vertical quadrant].each do |view|
      it "a short mail fits on #{device} #{view}" do
        msg = SIZED_MSG.merge(body: SIZED_BODY, paragraphs: SIZED_BODY.split("\n\n"), markdown: SIZED_BODY)
        screen = trmnl.render(view:, device:, now: SIZED_NOW, data: { data: { success: true, display: 'latest', email: 'me@example.com', folder: 'INBOX', message: msg } }, transform: false, custom_fields: SIZED_FIELDS)
        expect(screen).to have_text('Picking up the children today')
        expect(screen).to have_text('Thanks for your understanding!') if view == 'full'  # large, yet whole
        expect(screen).to have_no_overflow
        expect(screen).to match_snapshot
      end
    end
  end
end
