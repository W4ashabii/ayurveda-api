import mongoose, { Schema, Document } from 'mongoose';

export interface ICartItem {
  product: mongoose.Types.ObjectId;
  name: string;
  image: string;
  price: number;
  quantity: number;
}

export interface ICart extends Document {
  user: {
    email: string;
    name?: string;
  };
  items: ICartItem[];
  createdAt: Date;
  updatedAt: Date;
}

const CartItemSchema: Schema = new Schema({
  product: {
    type: Schema.Types.ObjectId,
    ref: 'Product',
    required: true,
  },
  name: { type: String, required: true },
  image: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true, min: 1 },
});

const CartSchema: Schema = new Schema(
  {
    user: {
      email: { type: String, required: true },
      name: { type: String },
    },
    items: [CartItemSchema],
  },
  {
    timestamps: true,
  }
);

// Ensure one cart per user (unique index)
CartSchema.index({ 'user.email': 1 }, { unique: true });

export default mongoose.model<ICart>('Cart', CartSchema);


