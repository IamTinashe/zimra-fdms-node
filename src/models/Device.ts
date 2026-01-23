/**
 * Device model
 */

export interface Device {
  deviceId: string;
  deviceSerialNo: string;
  deviceModelName: string;
  deviceModelVersion: string;
  status: 'Registered' | 'Active' | 'Suspended' | 'Deactivated';
}
