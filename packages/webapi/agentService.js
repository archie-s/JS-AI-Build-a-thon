import { AIProjectClient } from "@azure/ai-projects";
import { DefaultAzureCredential } from "@azure/identity";
import dotenv from "dotenv";

dotenv.config();

const agentThreads = {};

export class AgentService {
  constructor() {
    const endpoint = process.env.AZURE_PROJECT_ENDPOINT;

    if (!endpoint) {
      throw new Error("Missing AZURE_PROJECT_ENDPOINT in .env file");
    }

    this.client = new AIProjectClient(endpoint, new DefaultAzureCredential());

    this.agentId = process.env.AZURE_AGENT_ID;
    if (!this.agentId) {
      throw new Error("Missing AZURE_AGENT_ID in .env file");
    }

    console.log(" AIProjectClient initialized.");
  }

  async getOrCreateThread(sessionId) {
    if (!agentThreads[sessionId]) {
      console.log("🧵 Creating new thread...");
      const thread = await this.client.agents.threads.create();
      if (!thread?.id) throw new Error("Failed to create thread. No ID returned.");
      agentThreads[sessionId] = thread.id;
      console.log("🧵 Thread created:", thread.id);
    }
    return agentThreads[sessionId];
  }

  async processMessage(sessionId, message) {
    try {
      if (!message || typeof message !== "string" || message.trim() === "") {
        throw new Error(" Invalid user message. Must be a non-empty string.");
      }

      const threadId = await this.getOrCreateThread(sessionId);

      console.log(" Adding user message...");
      await this.client.agents.messages.create(threadId, {
        role: "user",
        content: message.trim(),
      });

      console.log("⚙️ Starting agent run...");
      let run = await this.client.agents.runs.create(threadId, this.agentId);

      while (["queued", "in_progress"].includes(run.status)) {
        console.log("Run status:", run.status);
        await new Promise((r) => setTimeout(r, 1000));
        run = await this.client.agents.runs.get(threadId, run.id);
      }

      if (run.status !== "completed") {
        console.error(` Run failed with status: ${run.status}`);
        return { reply: `Agent run failed (${run.status})` };
      }

      console.log(" Fetching messages...");
      const msgs = await this.client.agents.messages.list(threadId);

      const assistantMsgs = msgs.data
        ?.filter((m) => m.role === "assistant")
        ?.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      if (!assistantMsgs?.length) {
        return { reply: " No assistant reply received." };
      }

      const latest = assistantMsgs[0];
      const reply =
        latest.content
          ?.filter((c) => c.type === "text" && c.text?.value)
          ?.map((c) => c.text.value)
          ?.join("\n") || "⚠️ Assistant replied but no text found.";

      return { reply };
    } catch (err) {
      console.error(" Agent error:", err);
      return { reply: "Agent failed: " + (err?.message || "Unknown error") };
    }
  }
}
