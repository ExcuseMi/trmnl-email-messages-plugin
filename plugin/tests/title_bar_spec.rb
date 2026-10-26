# Hide Title Bar setting (owner 2026-10-26). Run: trmnlp test (from plugin/)
RSpec.describe 'Hide Title Bar' do
  { 'list' => DATA, 'latest' => latest_data, 'combined' => COMBINED_DATA }.each do |display, data|
    [true, false].each do |hidden|
      it "#{hidden ? 'hides' : 'shows'} the title bar for #{display}" do
        fields = FIELDS.merge(display:, hide_title_bar: hidden)
        screen = trmnl.render(view: 'full', now: NOW, data:, transform: false, custom_fields: fields)
        hidden ? expect(screen).to(have_no_css('.title_bar')) : expect(screen).to(have_css('.title_bar', count: 1))
        expect(screen).to have_no_overflow
      end
    end
  end

  it 'uses the room for more mail' do
    many = (1..30).map { |i| COMBINED_LIST.first.merge(subject: "Message #{i}", msg_id: i.to_s) }
    data = { data: COMBINED_DATA[:data].merge(display: 'list', messages: many, count: 30) }
    shown = trmnl.render(view: 'full', now: NOW, data:, transform: false, custom_fields: FIELDS)
    hidden = trmnl.render(view: 'full', now: NOW, data:, transform: false, custom_fields: FIELDS.merge(hide_title_bar: true))
    count = ->(screen) { screen.evaluate("[...document.querySelectorAll('.item')].filter(e => e.offsetParent !== null).length") }
    expect(count.(hidden)).to be > count.(shown)
  end
end
