import { addCredit, findById, updatePlan } from '../repositories/userRepository.js';
import * as coupons from '../repositories/couponRepository.js';

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

export const redeem = async (userId, code) => {
  const coupon = await coupons.getByCode(code);
  if (!coupon || coupon.uses_remaining <= 0) {
    const err = new Error('This code is not valid');
    err.status = 400;
    throw err;
  }
  const applied = await addCredit(userId, Number(coupon.value));
  await coupons.decrement(code);
  return { redeemed: true, value: Number(coupon.value), balance: Number(applied.credit) };
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
