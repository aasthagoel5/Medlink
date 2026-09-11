import { useState } from "react";
import { useNavigate } from "react-router";
import { MedlinkLogo } from "../components/Logo";
import { updateProfile } from "../lib/usersApi";

const BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"];

function TagInput({ label, placeholder, tags, setTags }) {
  const [input, setInput] = useState("");

  const addTag = () => {
    const trimmed = input.trim();
    if (trimmed && !tags.includes(trimmed)) {
      setTags([...tags, trimmed]);
    }
    setInput("");
  };

  const removeTag = (tag) => {
    setTags(tags.filter((t) => t !== tag));
  };

  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-sm font-medium text-slate-600">{label}</label>
      <div className="flex flex-wrap gap-2 mb-1">
        {tags.map((tag) => (
          <span
            key={tag}
            className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-[#F0FDFF] text-[#0891B2] border border-[#C8E4F0] rounded-full"
          >
            {tag}
            <button
              type="button"
              onClick={() => removeTag(tag)}
              className="hover:text-red-500"
            >
              ✕
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addTag();
            }
          }}
          placeholder={placeholder}
          className="flex-1 px-3.5 py-2 text-sm bg-white border border-[#C8E4F0] rounded-xl
                     focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
        />
        <button
          type="button"
          onClick={addTag}
          className="px-4 py-2 text-sm font-medium text-[#0891B2] bg-[#F0FDFF] border border-[#C8E4F0] rounded-xl hover:bg-[#E0FBFF]"
        >
          Add
        </button>
      </div>
    </div>
  );
}

export default function ProfileSetup() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [dateOfBirth, setDateOfBirth] = useState("");
  const [bloodGroup, setBloodGroup] = useState("");
  const [allergies, setAllergies] = useState([]);
  const [chronicConditions, setChronicConditions] = useState([]);
  const [contacts, setContacts] = useState([
    { name: "", phone: "", relation: "" },
  ]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const updateContact = (index, field, value) => {
    const updated = [...contacts];
    updated[index][field] = value;
    setContacts(updated);
  };

  const addContact = () =>
    setContacts([...contacts, { name: "", phone: "", relation: "" }]);
  const removeContact = (index) =>
    setContacts(contacts.filter((_, i) => i !== index));

  const handleFinish = async () => {
    setSaving(true);
    setError("");
    try {
      const validContacts = contacts.filter((c) => c.name && c.phone);
      await updateProfile({
        dateOfBirth,
        bloodGroup,
        allergies,
        chronicConditions,
        emergencyContacts: validContacts,
      });
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.message || "Failed to save profile");
    } finally {
      setSaving(false);
    }
  };

  const handleSkip = () => navigate("/dashboard");

  return (
    <div className="min-h-screen bg-[#F0F9FF] flex flex-col items-center py-10 px-4">
      <div className="mb-8">
        <MedlinkLogo size={36} showName />
      </div>

      <div
        className="w-full max-w-lg bg-white rounded-3xl border border-[#C8E4F0]/70 p-8"
        style={{
          boxShadow:
            "0 2px 12px rgba(8,145,178,0.06), 0 14px 48px rgba(8,145,178,0.08)",
        }}
      >
        {/* Progress indicator */}
        <div className="flex items-center gap-2 mb-8">
          {[1, 2].map((s) => (
            <div
              key={s}
              className={`h-1.5 flex-1 rounded-full ${s <= step ? "bg-[#0891B2]" : "bg-[#E5F0F6]"}`}
            />
          ))}
        </div>

        {error && (
          <div className="mb-4 px-3 py-2.5 rounded-lg bg-red-50 border border-red-100 text-sm text-red-600">
            {error}
          </div>
        )}

        {step === 1 && (
          <>
            <h1 className="font-display text-2xl font-bold text-[#0F172A] mb-1">
              Basic health info
            </h1>
            <p className="text-sm text-slate-500 mb-6">
              This helps us build your emergency profile.
            </p>

            <div className="flex flex-col gap-5">
              <div className="flex flex-col gap-1.5">
                <label className="text-sm font-medium text-slate-600">
                  Date of birth
                </label>
                <input
                  type="date"
                  value={dateOfBirth}
                  onChange={(e) => setDateOfBirth(e.target.value)}
                  className="px-3.5 py-2.5 text-sm bg-white border border-[#C8E4F0] rounded-xl
                             focus:outline-none focus:border-[#0891B2] focus:ring-2 focus:ring-[#0891B2]/15"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-sm font-medium text-slate-600">
                  Blood group
                </label>
                <div className="flex flex-wrap gap-2">
                  {BLOOD_GROUPS.map((bg) => (
                    <button
                      key={bg}
                      type="button"
                      onClick={() => setBloodGroup(bg)}
                      className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                        bloodGroup === bg
                          ? "bg-[#0891B2] text-white"
                          : "bg-white text-slate-500 border border-[#E5F0F6]"
                      }`}
                    >
                      {bg}
                    </button>
                  ))}
                </div>
              </div>

              <TagInput
                label="Known allergies"
                placeholder="e.g. Penicillin"
                tags={allergies}
                setTags={setAllergies}
              />
              <TagInput
                label="Chronic conditions"
                placeholder="e.g. Asthma"
                tags={chronicConditions}
                setTags={setChronicConditions}
              />
            </div>

            <div className="flex gap-3 mt-8">
              <button
                onClick={handleSkip}
                className="flex-1 py-2.5 text-sm font-medium text-slate-500 border border-[#E5F0F6] rounded-xl hover:bg-slate-50"
              >
                Skip for now
              </button>
              <button
                onClick={() => setStep(2)}
                className="flex-1 py-2.5 text-sm font-semibold text-white rounded-xl hover:opacity-90"
                style={{
                  background: "linear-gradient(135deg, #22D3EE, #0891B2)",
                }}
              >
                Continue
              </button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <h1 className="font-display text-2xl font-bold text-[#0F172A] mb-1">
              Emergency contacts
            </h1>
            <p className="text-sm text-slate-500 mb-6">
              Who should we notify if you need emergency access?
            </p>

            <div className="flex flex-col gap-4">
              {contacts.map((contact, i) => (
                <div
                  key={i}
                  className="p-4 rounded-xl border border-[#E5F0F6] flex flex-col gap-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400">
                      Contact {i + 1}
                    </span>
                    {contacts.length > 1 && (
                      <button
                        onClick={() => removeContact(i)}
                        className="text-xs text-red-500 hover:underline"
                      >
                        Remove
                      </button>
                    )}
                  </div>
                  <input
                    type="text"
                    placeholder="Name"
                    value={contact.name}
                    onChange={(e) => updateContact(i, "name", e.target.value)}
                    className="px-3 py-2 text-sm bg-white border border-[#C8E4F0] rounded-lg focus:outline-none focus:border-[#0891B2]"
                  />
                  <div className="grid grid-cols-2 gap-3">
                    <input
                      type="text"
                      placeholder="Phone"
                      value={contact.phone}
                      onChange={(e) =>
                        updateContact(i, "phone", e.target.value)
                      }
                      className="px-3 py-2 text-sm bg-white border border-[#C8E4F0] rounded-lg focus:outline-none focus:border-[#0891B2]"
                    />
                    <input
                      type="text"
                      placeholder="Relation (e.g. Mother)"
                      value={contact.relation}
                      onChange={(e) =>
                        updateContact(i, "relation", e.target.value)
                      }
                      className="px-3 py-2 text-sm bg-white border border-[#C8E4F0] rounded-lg focus:outline-none focus:border-[#0891B2]"
                    />
                  </div>
                </div>
              ))}

              <button
                onClick={addContact}
                className="text-sm text-[#0891B2] font-medium hover:underline text-left"
              >
                + Add another contact
              </button>
            </div>

            <div className="flex gap-3 mt-8">
              <button
                onClick={() => setStep(1)}
                className="flex-1 py-2.5 text-sm font-medium text-slate-500 border border-[#E5F0F6] rounded-xl hover:bg-slate-50"
              >
                Back
              </button>
              <button
                onClick={handleFinish}
                disabled={saving}
                className="flex-1 py-2.5 text-sm font-semibold text-white rounded-xl hover:opacity-90 disabled:opacity-50"
                style={{
                  background: "linear-gradient(135deg, #22D3EE, #0891B2)",
                }}
              >
                {saving ? "Saving..." : "Finish setup"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
