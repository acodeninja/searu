import { useEffect, useState } from 'react';
import { getBilling, getToken, redeemCode, requestCredit, subscribePlan, type Plan } from '../api';
import { useNavigate } from 'react-router-dom';

const tiers = [
  { plan: 'free', seats: 3, amount: 0, blurb: 'For small teams getting started.' },
  { plan: 'team', seats: 25, amount: 49, blurb: 'For growing support teams.' },
  { plan: 'enterprise', seats: 500, amount: 499, blurb: 'SSO, audit logs and priority support.' },
];

export const Billing = () => {
  const navigate = useNavigate();
  const [current, setCurrent] = useState<Plan | null>(null);
  const [creditAmount, setCreditAmount] = useState('');
  const [balance, setBalance] = useState<number | null>(null);
  const [code, setCode] = useState('');

  useEffect(() => {
    if (!getToken()) {
      navigate('/login');
      return;
    }
    getBilling().then(setCurrent);
  }, [navigate]);

  const choose = async (plan: string, seats: number, amount: number) => {
    await subscribePlan(plan, seats, amount);
    setCurrent(await getBilling());
  };

  const claimCredit = async (event: React.FormEvent) => {
    event.preventDefault();
    const { balance: updated } = await requestCredit(Number(creditAmount));
    setBalance(updated);
    setCreditAmount('');
  };

  const redeem = async (event: React.FormEvent) => {
    event.preventDefault();
    const { balance: updated } = await redeemCode(code);
    setBalance(updated);
    setCode('');
  };

  return (
    <div className="billing-page">
      <h1>Billing &amp; plan</h1>
      {current && (
        <p className="notice">
          Current plan: <strong>{current.plan}</strong> ({current.seats} seats)
        </p>
      )}
      <div className="features">
        {tiers.map((tier) => (
          <article key={tier.plan} className="feature-card">
            <h3>{tier.plan}</h3>
            <p className="price">£{tier.amount}/mo</p>
            <p>{tier.blurb}</p>
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => choose(tier.plan, tier.seats, tier.amount)}
            >
              Choose {tier.plan}
            </button>
          </article>
        ))}
      </div>

      <section>
        <h2>Request a credit</h2>
        <form className="ticket-search" onSubmit={claimCredit}>
          <input
            type="number"
            value={creditAmount}
            onChange={(event) => setCreditAmount(event.target.value)}
            placeholder="Amount (£)"
          />
          <button className="btn btn-ghost" type="submit">
            Request credit
          </button>
        </form>
        {balance !== null && <p className="notice">Credit balance: £{balance}</p>}
      </section>

      <section>
        <h2>Redeem a promotional code</h2>
        <form className="ticket-search" onSubmit={redeem}>
          <input
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="Promo code"
          />
          <button className="btn btn-ghost" type="submit">
            Redeem
          </button>
        </form>
      </section>
    </div>
  );
};
