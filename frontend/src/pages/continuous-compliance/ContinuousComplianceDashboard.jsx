import React from "react";

const cards = [
  "Regulatory Monitoring",
  "Compliance Drift",
  "Evidence Freshness",
  "Twilio Compliance Status",
  "Incident Monitoring",
  "Audit Readiness",
  "Compliance Tasks",
  "A2P Registration Status",
];

export default function ContinuousComplianceDashboard() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Continuous Compliance</h1>
        <p className="text-sm text-gray-600">
          Additive compliance operations views for regulatory monitoring, evidence freshness,
          Twilio validation, drift detection, incident monitoring, and audit readiness.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {cards.map((card) => (
          <div key={card} className="rounded-2xl border p-4 shadow-sm bg-white">
            <h2 className="font-medium">{card}</h2>
            <p className="text-sm text-gray-500 mt-2">
              Module scaffold created. Wire to /api/v2/continuous-compliance endpoints.
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
