import anthropic 
from click import prompt
from sentence_transformers import SentenceTransformer
from qdrant_client.models import Filter, FieldCondition, MatchValue
from src.modules.embeddings.qdrant_client import client as qdrant_client, COLLECTION_NAME

embed_model = SentenceTransformer('all-MiniLM-L6-v2')
anthropic_client = anthropic.Anthropic()

def ask_question(question: str, user_id: str) -> dict:
    # Step1 - Embed the question
    question_vector = embed_model.encode(question).tolist()

    # Step2 - Search for relevant chunks in Qdrant

    results = qdrant_client.query_points(
    collection_name=COLLECTION_NAME,
    query=question_vector,
    query_filter=Filter(
    must=[
          FieldCondition(
          key="userId",
          match=MatchValue(value=user_id)
        )
      ]
    ),
    limit=5,
  ).points  # You can adjust this number based on how many relevant chunks you want

    if not results:
      return {
            "answer": "I couldn't find anything in your uploaded records related to that question.",
            "sources": [],
      }
  #step 3 build context from the retrieved chunks
        
    context = "\n\n".join([r.payload["text"] for r in results])
    source_record_ids = list(set([r.payload["recordId"] for r in results]))

    prompt = f"""Here is relevant information from the patients'smedical records:

{context}

Based only on the information above , answer the patient's question. If the information doesn't fully answer the question, say so honestly rather than guessing. Do not provide medical advice, diagnoses, or dosage recommendations — only summarize what the records say.
Question : {question}"""

  #step 4 - Ask the question to the LLM 

    response = anthropic_client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens = 1000,
    messages =[{"role": "user" , "content": prompt}],

    )
    return {
      "answer" : response.content[0].text,
      "sources" : source_record_ids,
    }

