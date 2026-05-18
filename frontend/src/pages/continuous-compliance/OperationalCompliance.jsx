import React from "react";

export default function OperationalCompliance() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold">
        Continuous Compliance Operations
      </h1>

      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Regulatory Monitoring</h2>
          <p className="text-sm text-gray-500 mt-2">
            FCC, TCPA, CTIA, CASL, A2P, and vendor monitoring.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Messaging Compliance</h2>
          <p className="text-sm text-gray-500 mt-2">
            Suppression, opt-out handling, quiet-hour enforcement, and consent validation.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Compliance Drift</h2>
          <p className="text-sm text-gray-500 mt-2">
            Detect stale evidence, failed collectors, and baseline drift.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Evidence Freshness</h2>
          <p className="text-sm text-gray-500 mt-2">
            Operational evidence validity and review cadence tracking.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Incident Monitoring</h2>
          <p className="text-sm text-gray-500 mt-2">
            Messaging incidents, rejection spikes, suppression failures, and opt-out violations.
          </p>
        </div>

        <div className="rounded-2xl border p-4 shadow-sm bg-white">
          <h2 className="font-medium">Vendor Validation</h2>
          <p className="text-sm text-gray-500 mt-2">
            Twilio control-plane and external provider validation.
          </p>
        </div>

      </div>
    </div>
  );
}
