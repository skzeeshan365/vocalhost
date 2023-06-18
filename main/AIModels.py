from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


def generate_tags(input_data):
    # Initialize the tokenizer and model
    tokenizer = AutoTokenizer.from_pretrained(r"C:\Users\zeeshan\PycharmProjects\djangoProject1\Models/Tags")
    model = AutoModelForSeq2SeqLM.from_pretrained(r"C:\Users\zeeshan\PycharmProjects\djangoProject1\Models/Tags")

    inputs = tokenizer.encode(input_data, max_length=2048, truncation=True, padding="longest", return_tensors="pt")
    outputs = model.generate(inputs, num_beams=10, num_return_sequences=1, max_length=64, early_stopping=True)
    decoded_outputs = tokenizer.batch_decode(outputs, skip_special_tokens=True)
    return decoded_outputs


def summarize(input_data):
    tokenizer = AutoTokenizer.from_pretrained(r"C:\Users\zeeshan\PycharmProjects\djangoProject1\Models/Summary")
    model = AutoModelForSeq2SeqLM.from_pretrained(r"C:\Users\zeeshan\PycharmProjects\djangoProject1\Models/Summary")

    inputs = tokenizer.encode(input_data, max_length=2048, truncation=True, padding="longest", return_tensors="pt")
    outputs = model.generate(inputs, num_return_sequences=1, max_length=50, early_stopping=True)
    decoded_outputs = tokenizer.batch_decode(outputs, skip_special_tokens=True)[0]

    return decoded_outputs
