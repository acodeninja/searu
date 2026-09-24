import { useEffect, useState } from 'react';
import { getBilling, getToken, subscribePlan, type Plan } from '../api';
import { useNavigate } from 'react-router-dom';

const tiers = [
  { plan: 'free', seats: 3, amount: 0, blurb: 'For small teams getting started.' },
  { plan: 'team', seats: 25, amount: 49, blurb: 'For growing support teams.' },
  { plan: 'enterprise', seats: 500, amount: 499, blurb: 'SSO, audit logs and priority support.' },
];

export const Billing = () => {
  const navigate = useNavigate();
  const [current, setCurrent] = useState<Plan | null>(null);

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
    </div>
  );
};
