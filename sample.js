import ModelClient, { isUnexpected } from "@azure-rest/ai-inference";
import { AzureKeyCredential } from "@azure/core-auth";

const token = process.env["GITHUB_TOKEN"];
const endpoint = "https://models.github.ai/inference";
const model = "deepseek/DeepSeek-R1-0528";
import fs from "fs";

export async function main() {

  const imagePath = "./contoso_layout_sketch.jpg"; 
  const imageBuffer = fs.readFileSync(imagePath);
  const imageBase64 = imageBuffer.toString("base64");

  const client = ModelClient(
    endpoint,
    new AzureKeyCredential(token),
  );

  const response = await client.path("/chat/completions").post({
    body: {
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { 
          role: "user", 
          content: [
            { type: "text", text: "What is in this image?" },
            { type: "image", data: imageBase64, mime_type: "image/jpeg" }
          ]
        }
      ],
      max_tokens: 1000,
      model: model
    }
  });

  if (isUnexpected(response)) {
    throw response.body.error || response.body || response;
  }

  console.log(response.body.choices[0].message.content);
}

main().catch((err) => {
  console.error("The sample encountered an error:", err);
});

