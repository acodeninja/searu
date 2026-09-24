import { parseXml } from 'libxmljs2';

const catalogue = parseXml(`<catalogue>
  <service tier="public"><name>Dashboard</name><owner>platform</owner></service>
  <service tier="public"><name>REST API</name><owner>platform</owner></service>
  <service tier="public"><name>Ticketing</name><owner>support</owner></service>
  <service tier="internal"><name>Billing Ledger</name><owner>finance</owner><secret>ledger_key_9931f</secret></service>
  <service tier="internal"><name>Signing Service</name><owner>security</owner><secret>hsm_pin_4471</secret></service>
</catalogue>`);

const asRow = (node) => ({
  name: node.get('name')?.text(),
  owner: node.get('owner')?.text(),
  tier: node.attr('tier')?.value(),
  secret: node.get('secret')?.text() ?? null,
});

export const search = (term) => {
  const xpath = `//service[@tier='public' and contains(name,'${term}')]`;
  return catalogue.find(xpath).map(asRow);
};
