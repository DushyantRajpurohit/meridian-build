/**
 * Six-person clinic, one back-office box. The data layer is a pair of arrays on purpose: this
 * assignment is about the boundary in front of the code, and a database behind it would only
 * add moving parts to the demo.
 */

export interface Appointment {
  id: string
  name: string
  reason: string
  createdAt: string
}

export interface LabResult {
  id: string
  patient: string
  panel: string
  value: string
  receivedAt: string
}

export const appointments: Appointment[] = []

export const labResults: LabResult[] = [
  { id: 'lr-001', patient: 'A. Rao', panel: 'CBC', value: 'normal', receivedAt: '2026-08-20T09:14:00Z' },
]

export function addAppointment(name: string, reason: string): Appointment {
  const appointment: Appointment = {
    id: `ap-${(appointments.length + 1).toString().padStart(3, '0')}`,
    name,
    reason,
    createdAt: new Date().toISOString(),
  }
  appointments.push(appointment)
  return appointment
}
