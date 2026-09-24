import { findById, updatePlan } from '../repositories/userRepository.js';

export const currentPlan = async (userId) => {
  const user = await findById(userId);
  return { plan: user?.plan ?? 'free', seats: user?.seats ?? 3 };
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
