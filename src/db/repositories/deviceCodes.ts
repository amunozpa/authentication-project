import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { DeviceCodeRecord } from '../../types';

type CreateDeviceCodeInput = {
  device_code: string;
  user_code: string;
  expires_at: number;
};

export const deviceCodesRepository = {
  findByDeviceCode(deviceCode: string): DeviceCodeRecord | null {
    return (
      (db
        .prepare('SELECT * FROM device_codes WHERE device_code = ?')
        .get(deviceCode) as DeviceCodeRecord | undefined) ?? null
    );
  },

  findByUserCode(userCode: string): DeviceCodeRecord | null {
    return (
      (db
        .prepare(
          'SELECT * FROM device_codes WHERE user_code = ? AND expires_at > ? AND status = ?',
        )
        .get(userCode, Date.now(), 'pending') as DeviceCodeRecord | undefined) ?? null
    );
  },

  create(data: CreateDeviceCodeInput): DeviceCodeRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO device_codes (id, device_code, user_code, status, expires_at, created_at)
       VALUES (?, ?, ?, 'pending', ?, ?)`,
    ).run(id, data.device_code, data.user_code, data.expires_at, now);

    return db.prepare('SELECT * FROM device_codes WHERE id = ?').get(id) as DeviceCodeRecord;
  },

  approve(id: string, userId: string): void {
    db.prepare(
      "UPDATE device_codes SET status = 'approved', user_id = ? WHERE id = ?",
    ).run(userId, id);
  },

  deny(id: string): void {
    db.prepare("UPDATE device_codes SET status = 'denied' WHERE id = ?").run(id);
  },

  expire(id: string): void {
    db.prepare("UPDATE device_codes SET status = 'expired' WHERE id = ?").run(id);
  },
};
