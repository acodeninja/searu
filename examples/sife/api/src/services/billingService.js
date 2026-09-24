import { addCredit, findById, updatePlan } from '../repositories/userRepository.js';

export const currentPlan = async (userId) => {
  const user = await findById(userId);
  return { plan: user?.plan ?? 'free', seats: user?.seats ?? 3 };
};

export const refund = async (userId, amount) => {
  const applied = await addCredit(userId, Number(amount ?? 0));
  return {
    approved: true,
    status: 'auto-approved',
    amount: Number(amount ?? 0),
    balance: Number(applied.credit),
    currency: 'GBP',
  };
};

export const subscribe = async (userId, { plan, seats, amount }) => {
  const updated = await updatePlan(userId, plan ?? 'free', Number.parseInt(seats ?? 3, 10));
  return {
    ok: true,
    plan: updated.plan,
    seats: updated.seats,
    charged: Number(amount ?? 0),
    currency: 'GBP',
  };
};
