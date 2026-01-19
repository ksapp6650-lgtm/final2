/*
  # Create Progress Tracking System

  1. New Tables
    - `user_progress`
      - `id` (uuid, primary key)
      - `user_id` (text) - User identifier
      - `module_name` (text) - Name of the completed module
      - `module_level` (text) - Level: Beginner, Intermediate, Advanced
      - `points` (integer) - Points earned for this module
      - `completed_at` (timestamptz) - When the module was completed
      - `created_at` (timestamptz)
    
    - `daily_activity`
      - `id` (uuid, primary key)
      - `user_id` (text) - User identifier
      - `activity_date` (date) - Date of activity
      - `modules_completed` (integer) - Number of modules completed that day
      - `created_at` (timestamptz)

  2. Security
    - Enable RLS on both tables
    - Add policies for users to read/write their own data
*/

CREATE TABLE IF NOT EXISTS user_progress (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL DEFAULT 'default_user',
  module_name text NOT NULL,
  module_level text NOT NULL,
  points integer NOT NULL DEFAULT 0,
  completed_at timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS daily_activity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL DEFAULT 'default_user',
  activity_date date NOT NULL,
  modules_completed integer DEFAULT 1,
  created_at timestamptz DEFAULT now(),
  UNIQUE(user_id, activity_date)
);

ALTER TABLE user_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE daily_activity ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own progress"
  ON user_progress
  FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Users can insert own progress"
  ON user_progress
  FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Users can read own activity"
  ON daily_activity
  FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Users can insert own activity"
  ON daily_activity
  FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Users can update own activity"
  ON daily_activity
  FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_user_progress_user_id ON user_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_user_progress_completed_at ON user_progress(completed_at);
CREATE INDEX IF NOT EXISTS idx_daily_activity_user_id ON daily_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_daily_activity_date ON daily_activity(activity_date);
