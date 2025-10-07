-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "marketingOptIn" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "paymentPolicy" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "privacyPolicy" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "termsOfService" BOOLEAN NOT NULL DEFAULT false;
